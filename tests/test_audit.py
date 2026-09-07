"""Unit and integration tests for ELF binary mitigation auditing."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from elftools.elf.dynamic import DynamicSection
from typer.testing import CliRunner

from airgap_audit.audit import (
    ElfAuditor,
    MitigationStatus,
    NonElfError,
    PieLevel,
    RelroLevel,
    Severity,
)
from airgap_audit.cli import app
from airgap_audit.core.crypto import generate_key_pair, save_private_key

runner = CliRunner()
REAL_ARM64_BIN = Path("lvgl_gui/build/arm64-release/lvgl_gui")


def test_missing_file_raises_error(tmp_path: Path) -> None:
    """Auditing a non-existent file raises FileNotFoundError."""
    missing = tmp_path / "does_not_exist"
    with pytest.raises(FileNotFoundError):
        ElfAuditor(missing)


def test_non_elf_file_raises_error(tmp_path: Path) -> None:
    """Auditing a non-ELF file raises NonElfError."""
    text_file = tmp_path / "hello.txt"
    text_file.write_text("Hello world, not an ELF!")
    auditor = ElfAuditor(text_file)
    with pytest.raises(NonElfError):
        auditor.audit()


@pytest.mark.skipif(not REAL_ARM64_BIN.is_file(), reason="Real ARM64 binary not built")
def test_real_arm64_binary_audit() -> None:
    """Audit real compiled ARM64 lvgl_gui binary with full mitigations."""
    auditor = ElfAuditor(REAL_ARM64_BIN)
    report = auditor.audit()

    assert report.architecture == "AArch64"
    assert report.elf_class == 64
    assert report.endianness == "little"
    assert report.nx_enabled is True
    assert report.pie_level == PieLevel.FULL_PIE
    assert report.canary_present is True
    assert report.relro_level == RelroLevel.FULL
    assert report.score >= 90
    assert report.passed is True
    assert len(report.fortified_functions) > 0

    # Ensure all 7 checks exist
    check_names = {c.name for c in report.checks}
    assert "NX Stack Protection" in check_names
    assert "PIE / ASLR" in check_names
    assert "Stack Canary (SSP)" in check_names
    assert "RELRO (Read-Only Relocations)" in check_names
    assert "FORTIFY_SOURCE" in check_names
    assert "RPATH / RUNPATH Sanitization" in check_names
    assert "Stripped Symbols" in check_names


def test_nx_stack_detection_scenarios(tmp_path: Path) -> None:
    """Test NX check when segment is missing or executable."""
    dummy_file = tmp_path / "dummy_elf"
    dummy_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

    auditor = ElfAuditor(dummy_file)

    # 1. Missing PT_GNU_STACK
    mock_elf = MagicMock()
    mock_elf.iter_segments.return_value = []
    enabled, check = auditor._check_nx(mock_elf)
    assert enabled is False
    assert check.status == MitigationStatus.FAIL
    assert check.severity == Severity.CRITICAL

    # 2. Executable stack (PF_X bit = 0x1)
    mock_seg = {"p_type": "PT_GNU_STACK", "p_flags": 0x7}  # RWX
    mock_elf.iter_segments.return_value = [mock_seg]
    enabled, check = auditor._check_nx(mock_elf)
    assert enabled is False
    assert check.status == MitigationStatus.FAIL

    # 3. Non-executable stack (RW = 0x6, PF_X bit = 0)
    mock_seg = {"p_type": "PT_GNU_STACK", "p_flags": 0x6}  # RW
    mock_elf.iter_segments.return_value = [mock_seg]
    enabled, check = auditor._check_nx(mock_elf)
    assert enabled is True
    assert check.status == MitigationStatus.PASS


def test_pie_detection_scenarios(tmp_path: Path) -> None:
    """Test PIE check for ET_EXEC, ET_DYN, and shared libraries."""
    dummy_file = tmp_path / "dummy_elf"
    dummy_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

    auditor = ElfAuditor(dummy_file)

    # 1. Non-PIE (ET_EXEC)
    mock_elf = MagicMock()
    mock_elf.header = {"e_type": "ET_EXEC"}
    pie_level, check = auditor._check_pie(mock_elf)
    assert pie_level == PieLevel.NONE
    assert check.status == MitigationStatus.FAIL

    # 2. PIE executable (ET_DYN with DT_DEBUG)
    mock_elf.header = {"e_type": "ET_DYN"}
    mock_dyn = MagicMock(spec=DynamicSection)
    mock_tag = MagicMock()
    mock_tag.entry.d_tag = "DT_DEBUG"
    mock_dyn.iter_tags.return_value = [mock_tag]
    mock_elf.get_section_by_name.return_value = mock_dyn
    pie_level, check = auditor._check_pie(mock_elf)
    assert pie_level == PieLevel.FULL_PIE
    assert check.status == MitigationStatus.PASS


def test_relro_detection_scenarios(tmp_path: Path) -> None:
    """Test RELRO check for No RELRO, Partial RELRO, and Full RELRO."""
    dummy_file = tmp_path / "dummy_elf"
    dummy_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

    auditor = ElfAuditor(dummy_file)

    # 1. No RELRO (Missing PT_GNU_RELRO segment)
    mock_elf = MagicMock()
    mock_elf.iter_segments.return_value = []
    level, check = auditor._check_relro(mock_elf)
    assert level == RelroLevel.NONE
    assert check.status == MitigationStatus.FAIL

    # 2. Partial RELRO (PT_GNU_RELRO present, no BIND_NOW)
    mock_elf.iter_segments.return_value = [{"p_type": "PT_GNU_RELRO"}]
    mock_dyn = MagicMock(spec=DynamicSection)
    mock_dyn.iter_tags.return_value = []
    mock_elf.get_section_by_name.return_value = mock_dyn
    level, check = auditor._check_relro(mock_elf)
    assert level == RelroLevel.PARTIAL
    assert check.status == MitigationStatus.WARN

    # 3. Full RELRO (PT_GNU_RELRO + DT_BIND_NOW)
    mock_tag = MagicMock()
    mock_tag.entry.d_tag = "DT_BIND_NOW"
    mock_dyn.iter_tags.return_value = [mock_tag]
    level, check = auditor._check_relro(mock_elf)
    assert level == RelroLevel.FULL
    assert check.status == MitigationStatus.PASS


def test_canary_detection_scenarios(tmp_path: Path) -> None:
    """Test stack canary detection with and without symbols."""
    dummy_file = tmp_path / "dummy_elf"
    dummy_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

    auditor = ElfAuditor(dummy_file)

    # 1. No canary symbols
    mock_elf = MagicMock()
    mock_elf.get_section_by_name.return_value = None
    present, check = auditor._check_canary(mock_elf)
    assert present is False
    assert check.status == MitigationStatus.FAIL

    # 2. Canary symbol present
    from elftools.elf.sections import SymbolTableSection

    mock_symtab = MagicMock(spec=SymbolTableSection)
    mock_sym = MagicMock()
    mock_sym.name = "__stack_chk_fail"
    mock_symtab.iter_symbols.return_value = [mock_sym]
    mock_elf.get_section_by_name.side_effect = lambda name: mock_symtab if name == ".symtab" else None
    present, check = auditor._check_canary(mock_elf)
    assert present is True
    assert check.status == MitigationStatus.PASS


def test_rpath_detection_scenarios(tmp_path: Path) -> None:
    """Test detection of dangerous RPATH/RUNPATH entries."""
    dummy_file = tmp_path / "dummy_elf"
    dummy_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

    auditor = ElfAuditor(dummy_file)

    # 1. Insecure relative path '.' in RUNPATH
    mock_elf = MagicMock()
    mock_dyn = MagicMock(spec=DynamicSection)
    mock_tag = MagicMock()
    mock_tag.entry.d_tag = "DT_RUNPATH"
    mock_tag.runpath = "/usr/lib:.:/opt/app"
    mock_dyn.iter_tags.return_value = [mock_tag]
    mock_elf.get_section_by_name.return_value = mock_dyn
    _, _, check = auditor._check_rpath(mock_elf)
    assert check.status == MitigationStatus.FAIL
    assert "Insecure search path" in check.summary

    # 2. Safe RUNPATH
    mock_tag.runpath = "/usr/lib/airgap:/opt/app/lib"
    _, _, check = auditor._check_rpath(mock_elf)
    assert check.status == MitigationStatus.PASS


@pytest.mark.skipif(not REAL_ARM64_BIN.is_file(), reason="Real ARM64 binary not built")
def test_cli_audit_table_format() -> None:
    """Test CLI audit elf command with human-readable table."""
    result = runner.invoke(app, ["audit", "elf", str(REAL_ARM64_BIN)])
    assert result.exit_code == 0
    assert "ELF Binary Metadata" in result.output
    assert "NX Stack Protection" in result.output
    assert "Hardening Score: 100%" in result.output
    assert "[PASS] Binary satisfies all mitigation requirements." in result.output


@pytest.mark.skipif(not REAL_ARM64_BIN.is_file(), reason="Real ARM64 binary not built")
def test_cli_audit_json_format() -> None:
    """Test CLI audit elf command with JSON format."""
    import json

    result = runner.invoke(app, ["audit", "elf", str(REAL_ARM64_BIN), "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["architecture"] == "AArch64"
    assert data["score"] == 100
    assert data["passed"] is True
    assert data["nx_enabled"] is True


def test_cli_audit_nonexistent_binary() -> None:
    """Test CLI audit elf command fails gracefully on missing file."""
    result = runner.invoke(app, ["audit", "elf", "non_existent_binary"])
    assert result.exit_code != 0
    assert "Audit failed" in result.output


@pytest.mark.skipif(not REAL_ARM64_BIN.is_file(), reason="Real ARM64 binary not built")
def test_cli_package_create_with_audit(tmp_path: Path) -> None:
    """Test package create with --audit pre-flight check."""
    priv, _ = generate_key_pair()
    priv_file = tmp_path / "priv.pem"
    save_private_key(priv, priv_file)
    out_pkg = tmp_path / "output.update"

    result = runner.invoke(
        app,
        [
            "package",
            "create",
            "--payload",
            str(REAL_ARM64_BIN),
            "--key",
            str(priv_file),
            "--out",
            str(out_pkg),
            "--audit",
        ],
    )
    assert result.exit_code == 0
    assert "Running pre-flight binary mitigation audit" in result.output
    assert "Sealed Container Created" in result.output
    assert out_pkg.is_file()
