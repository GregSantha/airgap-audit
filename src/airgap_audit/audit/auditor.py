"""ELF binary exploit mitigation auditor using pyelftools."""

from __future__ import annotations

import hashlib
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from airgap_audit.audit.models import (
    AuditReport,
    MitigationCheck,
    MitigationStatus,
    PieLevel,
    RelroLevel,
    Severity,
)

# Common dangerous paths in RPATH/RUNPATH
INSECURE_PATH_SUBSTRINGS = (".", "./", "/tmp", "/var/tmp", "/dev/shm")


class AuditError(Exception):
    """Base exception for binary audit errors."""


class NonElfError(AuditError):
    """Raised when target file is not a valid ELF binary."""


class ElfAuditor:
    """
    Analyzes ELF binaries for compile-time and link-time security mitigations.

    Checks:
    - NX (No-Execute stack / PT_GNU_STACK)
    - PIE (Position Independent Executable / ASLR readiness)
    - Stack Canary (Stack Smashing Protection / __stack_chk_fail)
    - RELRO (Full vs. Partial Read-Only Relocations)
    - FORTIFY_SOURCE (Bounds-checked libc functions)
    - RPATH / RUNPATH (Insecure dynamic library search paths)
    - Symbol stripping status (.symtab section)
    """

    def __init__(self, target_path: Path) -> None:
        self.target_path = Path(target_path).resolve()
        if not self.target_path.is_file():
            raise FileNotFoundError(f"Binary file not found: {self.target_path}")

    def _compute_sha256(self) -> str:
        sha = hashlib.sha256()
        with open(self.target_path, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        return sha.hexdigest()

    def audit(self) -> AuditReport:
        """Run full binary mitigation audit and return an AuditReport."""
        try:
            with open(self.target_path, "rb") as f:
                elf = ELFFile(f)
                return self._evaluate_elf(elf)
        except ELFError as exc:
            raise NonElfError(f"File is not a valid ELF binary ({self.target_path.name}): {exc}") from exc

    def _evaluate_elf(self, elf: ELFFile) -> AuditReport:
        checks: list[MitigationCheck] = []

        # 1. NX Check (PT_GNU_STACK)
        nx_enabled, nx_check = self._check_nx(elf)
        checks.append(nx_check)

        # 2. PIE Check (e_type + dynamic tags)
        pie_level, pie_check = self._check_pie(elf)
        checks.append(pie_check)

        # 3. Stack Canary Check (symbols)
        canary_present, canary_check = self._check_canary(elf)
        checks.append(canary_check)

        # 4. RELRO Check (PT_GNU_RELRO + BIND_NOW)
        relro_level, relro_check = self._check_relro(elf)
        checks.append(relro_check)

        # 5. FORTIFY_SOURCE Check
        fortified_funcs, fortify_check = self._check_fortify(elf)
        checks.append(fortify_check)

        # 6. RPATH / RUNPATH Check
        rpath, runpath, rpath_check = self._check_rpath(elf)
        checks.append(rpath_check)

        # 7. Stripped Symbols Check
        is_stripped, stripped_check = self._check_stripped(elf)
        checks.append(stripped_check)

        # Compute Score (0 - 100)
        total_possible = sum(c.weight for c in checks if c.weight > 0)
        earned = 0
        for c in checks:
            if c.weight <= 0:
                continue
            if c.status == MitigationStatus.PASS:
                earned += c.weight
            elif c.status == MitigationStatus.WARN:
                earned += c.weight // 2

        score = int((earned / total_possible) * 100) if total_possible > 0 else 0

        # Mandatory pass criteria: NX, Canary, PIE (not NONE), and Full RELRO
        passed = bool(nx_enabled and canary_present and pie_level != PieLevel.NONE and relro_level == RelroLevel.FULL)

        return AuditReport(
            target_path=str(self.target_path),
            file_size=self.target_path.stat().st_size,
            sha256=self._compute_sha256(),
            architecture=elf.get_machine_arch(),
            elf_class=elf.elfclass,
            endianness="little" if elf.little_endian else "big",
            nx_enabled=nx_enabled,
            pie_level=pie_level,
            relro_level=relro_level,
            canary_present=canary_present,
            fortified_functions=fortified_funcs,
            rpath=rpath,
            runpath=runpath,
            is_stripped=is_stripped,
            checks=checks,
            score=score,
            passed=passed,
        )

    def _check_nx(self, elf: ELFFile) -> tuple[bool, MitigationCheck]:
        """Check for Non-Executable Stack (PT_GNU_STACK)."""
        stack_seg = None
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_GNU_STACK":
                stack_seg = seg
                break

        if stack_seg is None:
            return False, MitigationCheck(
                name="NX Stack Protection",
                status=MitigationStatus.FAIL,
                severity=Severity.CRITICAL,
                cwe_id="CWE-119",
                summary="Missing PT_GNU_STACK segment; stack may default to executable.",
                details="No PT_GNU_STACK program header found in ELF headers.",
                remediation="-Wl,-z,noexecstack",
                weight=20,
            )

        # PF_X is bit 0x1 (execute permission)
        is_executable = bool(stack_seg["p_flags"] & 0x1)
        if is_executable:
            return False, MitigationCheck(
                name="NX Stack Protection",
                status=MitigationStatus.FAIL,
                severity=Severity.CRITICAL,
                cwe_id="CWE-119",
                summary="Stack memory is EXECUTABLE (NX disabled). Shellcode can run on stack.",
                details=f"PT_GNU_STACK flags = {hex(stack_seg['p_flags'])} (includes PF_X execute flag).",
                remediation="-Wl,-z,noexecstack",
                weight=20,
            )

        return True, MitigationCheck(
            name="NX Stack Protection",
            status=MitigationStatus.PASS,
            severity=Severity.INFO,
            cwe_id="CWE-119",
            summary="Stack is non-executable (NX enabled).",
            details="PT_GNU_STACK permissions are Read/Write (RW) without execute (PF_X).",
            remediation="Already enforced",
            weight=20,
        )

    def _check_pie(self, elf: ELFFile) -> tuple[PieLevel, MitigationCheck]:
        """Check for Position Independent Executable (ASLR support)."""
        e_type = elf.header["e_type"]

        if e_type == "ET_EXEC":
            return PieLevel.NONE, MitigationCheck(
                name="PIE / ASLR",
                status=MitigationStatus.FAIL,
                severity=Severity.HIGH,
                cwe_id="CWE-119",
                summary="Fixed base address (No PIE). Ineffective against ROP / ret2libc attacks.",
                details="ELF type is ET_EXEC (standard non-relocatable executable).",
                remediation="-fPIE -pie",
                weight=20,
            )

        if e_type == "ET_DYN":
            dyn = elf.get_section_by_name(".dynamic")
            has_debug = False
            if isinstance(dyn, DynamicSection):
                for tag in dyn.iter_tags():
                    if tag.entry.d_tag == "DT_DEBUG":
                        has_debug = True
                        break

            if has_debug:
                return PieLevel.FULL_PIE, MitigationCheck(
                    name="PIE / ASLR",
                    status=MitigationStatus.PASS,
                    severity=Severity.INFO,
                    cwe_id="CWE-119",
                    summary="Full PIE. ASLR randomizes base address.",
                    details="ELF type is ET_DYN with DT_DEBUG present (PIE executable).",
                    remediation="Already enforced",
                    weight=20,
                )
            return PieLevel.DSO, MitigationCheck(
                name="PIE / ASLR",
                status=MitigationStatus.PASS,
                severity=Severity.INFO,
                cwe_id="CWE-119",
                summary="Dynamic Shared Object / Position Independent (ET_DYN).",
                details="ELF type is ET_DYN (relocatable shared library/binary).",
                remediation="Already enforced",
                weight=20,
            )

        return PieLevel.NONE, MitigationCheck(
            name="PIE / ASLR",
            status=MitigationStatus.WARN,
            severity=Severity.MEDIUM,
            cwe_id="CWE-119",
            summary=f"Unrecognized ELF type: {e_type}.",
            details=f"Header e_type = {e_type}",
            remediation="-fPIE -pie",
            weight=20,
        )

    def _check_canary(self, elf: ELFFile) -> tuple[bool, MitigationCheck]:
        """Check for stack canaries (__stack_chk_fail)."""
        canary_found = False

        for s_name in (".symtab", ".dynsym"):
            sec = elf.get_section_by_name(s_name)
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    if sym.name in ("__stack_chk_fail", "__stack_chk_guard", "__intel_security_cookie"):
                        canary_found = True
                        break
            if canary_found:
                break

        if canary_found:
            return True, MitigationCheck(
                name="Stack Canary (SSP)",
                status=MitigationStatus.PASS,
                severity=Severity.INFO,
                cwe_id="CWE-121",
                summary="Stack canary symbols detected (__stack_chk_fail).",
                details="Found '__stack_chk_fail' in symbol tables.",
                remediation="Already enforced",
                weight=20,
            )

        return False, MitigationCheck(
            name="Stack Canary (SSP)",
            status=MitigationStatus.FAIL,
            severity=Severity.CRITICAL,
            cwe_id="CWE-121",
            summary="No stack canary symbols detected. Vulnerable to stack buffer overflows.",
            details="Neither '__stack_chk_fail' nor '__stack_chk_guard' found in symbols.",
            remediation="-fstack-protector-strong",
            weight=20,
        )

    def _check_relro(self, elf: ELFFile) -> tuple[RelroLevel, MitigationCheck]:
        """Check for Read-Only Relocations (Partial vs. Full RELRO)."""
        has_relro_seg = False
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_GNU_RELRO":
                has_relro_seg = True
                break

        if not has_relro_seg:
            return RelroLevel.NONE, MitigationCheck(
                name="RELRO (Read-Only Relocations)",
                status=MitigationStatus.FAIL,
                severity=Severity.CRITICAL,
                cwe_id="CWE-123",
                summary="No RELRO. Global Offset Table (GOT) and sections are completely writable.",
                details="Missing PT_GNU_RELRO program header.",
                remediation="-Wl,-z,relro,-z,now",
                weight=20,
            )

        # Check dynamic section for BIND_NOW flags
        dyn = elf.get_section_by_name(".dynamic")
        bind_now = False
        if isinstance(dyn, DynamicSection):
            for tag in dyn.iter_tags():
                if tag.entry.d_tag == "DT_BIND_NOW":
                    bind_now = True
                    break
                if tag.entry.d_tag == "DT_FLAGS_1" and (tag.entry.d_val & 0x1):  # DF_1_NOW = 0x1
                    bind_now = True
                    break
                if tag.entry.d_tag == "DT_FLAGS" and (tag.entry.d_val & 0x8):  # DF_BIND_NOW = 0x8
                    bind_now = True
                    break

        if bind_now:
            return RelroLevel.FULL, MitigationCheck(
                name="RELRO (Read-Only Relocations)",
                status=MitigationStatus.PASS,
                severity=Severity.INFO,
                cwe_id="CWE-123",
                summary="Full RELRO enabled. GOT marked read-only.",
                details="PT_GNU_RELRO present and DT_BIND_NOW / DF_1_NOW flag active.",
                remediation="Already enforced",
                weight=20,
            )

        return RelroLevel.PARTIAL, MitigationCheck(
            name="RELRO (Read-Only Relocations)",
            status=MitigationStatus.WARN,
            severity=Severity.MEDIUM,
            cwe_id="CWE-123",
            summary="Partial RELRO only. GOT table remains writable after startup (lazy binding).",
            details="PT_GNU_RELRO present, but DT_BIND_NOW is missing.",
            remediation="-Wl,-z,now",
            weight=20,
        )

    def _check_fortify(self, elf: ELFFile) -> tuple[list[str], MitigationCheck]:
        """Check for FORTIFY_SOURCE functions (*_chk)."""
        fortified: set[str] = set()

        for s_name in (".dynsym", ".symtab"):
            sec = elf.get_section_by_name(s_name)
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    if sym.name.endswith("_chk"):
                        fortified.add(sym.name)

        fortified_list = sorted(fortified)
        if fortified_list:
            sample = ", ".join(fortified_list[:4])
            if len(fortified_list) > 4:
                sample += f" (+{len(fortified_list) - 4} more)"
            return fortified_list, MitigationCheck(
                name="FORTIFY_SOURCE",
                status=MitigationStatus.PASS,
                severity=Severity.INFO,
                cwe_id="CWE-120",
                summary=f"Discovered {len(fortified_list)} fortified standard library functions.",
                details=f"Fortified symbols: {sample}",
                remediation="Already enforced",
                weight=10,
            )

        return [], MitigationCheck(
            name="FORTIFY_SOURCE",
            status=MitigationStatus.WARN,
            severity=Severity.LOW,
            cwe_id="CWE-120",
            summary="No fortified standard library functions discovered.",
            details="No symbols ending in '_chk' found in symbol tables.",
            remediation="-D_FORTIFY_SOURCE=3 -O2",
            weight=10,
        )

    def _check_rpath(self, elf: ELFFile) -> tuple[str | None, str | None, MitigationCheck]:
        """Check for dangerous DT_RPATH or DT_RUNPATH entries."""
        rpath: str | None = None
        runpath: str | None = None

        dyn = elf.get_section_by_name(".dynamic")
        if isinstance(dyn, DynamicSection):
            for tag in dyn.iter_tags():
                if tag.entry.d_tag == "DT_RPATH":
                    rpath = str(getattr(tag, "rpath", ""))
                elif tag.entry.d_tag == "DT_RUNPATH":
                    runpath = str(getattr(tag, "runpath", ""))

        dangerous_paths: list[str] = []
        for path_str in (rpath, runpath):
            if path_str:
                for segment in path_str.split(":"):
                    clean_seg = segment.strip()
                    if any(clean_seg == p or clean_seg.startswith(p + "/") for p in INSECURE_PATH_SUBSTRINGS):
                        dangerous_paths.append(clean_seg)

        if dangerous_paths:
            return (
                rpath,
                runpath,
                MitigationCheck(
                    name="RPATH / RUNPATH Sanitization",
                    status=MitigationStatus.FAIL,
                    severity=Severity.HIGH,
                    cwe_id="CWE-426",
                    summary="Insecure search path in RPATH/RUNPATH (untrusted library hijacking risk).",
                    details=f"Insecure path entries detected: {', '.join(dangerous_paths)}",
                    remediation="Remove relative/writable paths from RPATH/RUNPATH or use -Wl,--disable-new-dtags",
                    weight=10,
                ),
            )

        if rpath is not None:
            return (
                rpath,
                runpath,
                MitigationCheck(
                    name="RPATH / RUNPATH Sanitization",
                    status=MitigationStatus.WARN,
                    severity=Severity.LOW,
                    cwe_id="CWE-426",
                    summary="Legacy DT_RPATH detected. Prefer modern DT_RUNPATH.",
                    details=f"DT_RPATH = {rpath}",
                    remediation="-Wl,--enable-new-dtags",
                    weight=10,
                ),
            )

        return (
            rpath,
            runpath,
            MitigationCheck(
                name="RPATH / RUNPATH Sanitization",
                status=MitigationStatus.PASS,
                severity=Severity.INFO,
                cwe_id="CWE-426",
                summary="No insecure or rogue library search paths detected.",
                details=f"RUNPATH: {runpath or 'None'}, RPATH: None",
                remediation="Already enforced",
                weight=10,
            ),
        )

    def _check_stripped(self, elf: ELFFile) -> tuple[bool, MitigationCheck]:
        """Check if local/debug symbols (.symtab) have been stripped."""
        symtab = elf.get_section_by_name(".symtab")
        is_stripped = symtab is None

        if is_stripped:
            return True, MitigationCheck(
                name="Stripped Symbols",
                status=MitigationStatus.PASS,
                severity=Severity.INFO,
                cwe_id="CWE-200",
                summary="Binary is stripped. Symbol information removed to hinder reverse engineering.",
                details="No .symtab section present in binary.",
                remediation="Already enforced",
                weight=0,  # Informational hygiene, not a fatal exploit prevention mitigation
            )

        return False, MitigationCheck(
            name="Stripped Symbols",
            status=MitigationStatus.INFO,
            severity=Severity.LOW,
            cwe_id="CWE-200",
            summary="Binary is not stripped (.symtab section is present).",
            details="Local symbol table (.symtab) retained.",
            remediation="Run 'strip --strip-unneeded <binary>' for production builds",
            weight=0,
        )
