"""Data models for ELF binary mitigation auditing."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class MitigationStatus(str, Enum):
    """Mitigation check status."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    INFO = "INFO"


class Severity(str, Enum):
    """Severity of a missing or deficient mitigation."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RelroLevel(str, Enum):
    """RELRO (Relocation Read-Only) level."""

    NONE = "NO RELRO"
    PARTIAL = "PARTIAL RELRO"
    FULL = "FULL RELRO"


class PieLevel(str, Enum):
    """Position Independent Executable level."""

    NONE = "NO PIE"
    DSO = "DSO / SHARED LIB"
    FULL_PIE = "FULL PIE"


class MitigationCheck(BaseModel):
    """Result of an individual exploit mitigation check."""

    name: str = Field(description="Name of the mitigation (e.g. 'NX Stack', 'Stack Canary')")
    status: MitigationStatus = Field(description="Evaluation status: PASS, FAIL, WARN, INFO")
    severity: Severity = Field(description="Risk severity if missing")
    cwe_id: str = Field(description="Mapped CWE identifier (e.g. 'CWE-119')")
    summary: str = Field(description="Short human-readable summary of the check result")
    details: str = Field(description="Technical details discovered in the ELF file")
    remediation: str = Field(description="Recommended compiler/linker flag to enforce this mitigation")
    weight: int = Field(default=20, description="Weight used in total hardening score calculation (0-100)")


class AuditReport(BaseModel):
    """Comprehensive binary mitigation audit report."""

    target_path: str = Field(description="Filesystem path of the audited ELF binary")
    file_size: int = Field(description="File size in bytes")
    sha256: str = Field(description="SHA-256 digest of the binary")
    architecture: str = Field(description="Target machine architecture (e.g. AArch64, x86_64)")
    elf_class: int = Field(description="ELF class (32-bit or 64-bit)")
    endianness: str = Field(description="Little or big endian")

    # Detailed status fields
    nx_enabled: bool = Field(description="Whether NX (No-Execute stack) is active")
    pie_level: PieLevel = Field(description="Position Independent Executable level")
    relro_level: RelroLevel = Field(description="RELRO hardening level")
    canary_present: bool = Field(description="Whether stack canaries are active")
    fortified_functions: list[str] = Field(default_factory=list, description="List of fortified functions discovered")
    rpath: str | None = Field(default=None, description="DT_RPATH dynamic tag content if present")
    runpath: str | None = Field(default=None, description="DT_RUNPATH dynamic tag content if present")
    is_stripped: bool = Field(description="Whether debug/local symbols (.symtab) are stripped")

    # Aggregate evaluation
    checks: list[MitigationCheck] = Field(default_factory=list, description="Individual mitigation check results")
    score: int = Field(description="Total hardening score from 0 to 100")
    passed: bool = Field(description="True if all critical mitigations (NX, Canary, PIE, Full RELRO) passed")
