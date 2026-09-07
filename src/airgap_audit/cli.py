"""Command-line interface for airgap-audit."""

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from airgap_audit.audit import (
    AuditError,
    AuditReport,
    ElfAuditor,
    MitigationStatus,
    NonElfError,
)
from airgap_audit.core.container import (
    ContainerError,
    inspect_container,
    pack_container,
    unpack_and_verify,
)
from airgap_audit.core.crypto import (
    CryptoError,
    generate_key_pair,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
)
from airgap_audit.core.version import (
    find_version_header,
    parse_version_header,
    semver_to_code,
)

app = typer.Typer(
    name="airgap-audit",
    help="Offline USB update manager & binary security auditor for embedded Linux applications.",
    no_args_is_help=True,
)
package_app = typer.Typer(
    name="package",
    help="Create, verify, and inspect signed .update container packages.",
    no_args_is_help=True,
)
app.add_typer(package_app, name="package")

audit_app = typer.Typer(
    name="audit",
    help="Audit ELF binaries and embedded applications for compile/link security mitigations.",
    no_args_is_help=True,
)
app.add_typer(audit_app, name="audit")

console = Console()


@app.command()
def version() -> None:
    """Print the airgap-audit version."""
    from airgap_audit import __version__

    console.print(f"[bold cyan]airgap-audit[/bold cyan] version [green]{__version__}[/green]")


@app.command()
def keygen(
    out_dir: Annotated[
        Path,
        typer.Option("--out-dir", "-o", help="Directory where PEM keys will be saved."),
    ] = Path("./keys"),
) -> None:
    """Generate a new Ed25519 asymmetric keypair for package signing."""
    priv, pub = generate_key_pair()
    priv_path = out_dir / "private_key.pem"
    pub_path = out_dir / "public_key.pem"

    save_private_key(priv, priv_path)
    save_public_key(pub, pub_path)

    console.print(
        Panel.fit(
            f"[bold green]✓ Ed25519 Keypair Generated Successfully[/bold green]\n\n"
            f"[bold]Private Key (Dev/CI):[/bold] [yellow]{priv_path}[/yellow] (mode 0600)\n"
            f"[bold]Public Key  (Target):[/bold] [cyan]{pub_path}[/cyan]",
            title="Cryptographic Keygen",
            border_style="green",
        )
    )


@package_app.command("create")
def package_create(
    payload: Annotated[Path, typer.Option("--payload", "-p", help="Executable ELF binary to wrap.")],
    key: Annotated[Path, typer.Option("--key", "-k", help="Path to Ed25519 private key PEM file.")],
    out: Annotated[Path, typer.Option("--out", "-o", help="Output .update container filepath.")],
    version: Annotated[
        str | None,
        typer.Option("--version", "-v", help="Feature version (e.g. '0.1.0' or 100). Defaults to version.h."),
    ] = None,
    epoch: Annotated[
        int | None,
        typer.Option("--epoch", "-e", help="Security epoch for anti-rollback. Defaults to version.h."),
    ] = None,
    device_id: Annotated[
        str | None,
        typer.Option("--device-id", "-d", help="Target device identifier. Defaults to version.h."),
    ] = None,
    audit_preflight: Annotated[
        bool,
        typer.Option("--audit", help="Run pre-flight binary mitigation audit before packaging."),
    ] = False,
) -> None:
    """Pack and sign an ELF binary into a sealed .update container."""
    if audit_preflight:
        console.print("[dim cyan]ℹ Running pre-flight binary mitigation audit...[/dim cyan]")
        try:
            auditor = ElfAuditor(payload)
            audit_rep = auditor.audit()
            _render_audit_table(audit_rep)
            if not audit_rep.passed:
                console.print(
                    "[bold red][ERROR][/bold red] Pre-flight audit failed: "
                    "Payload lacks critical exploit mitigations. Aborting packaging."
                )
                sys.exit(1)
        except (NonElfError, AuditError) as exc:
            console.print(f"[bold red][ERROR][/bold red] Pre-flight audit failed: {exc}")
            sys.exit(1)
    # Attempt auto-detection from C++ version.h header if any metadata is omitted
    header_info = None
    if version is None or epoch is None or device_id is None:
        header_file = find_version_header(payload)
        if header_file:
            try:
                header_info = parse_version_header(header_file)
            except (OSError, ValueError) as exc:
                console.print(f"[dim yellow]Warning: Failed to parse {header_file}: {exc}[/dim yellow]")

    # Resolve version
    resolved_version_code: int
    if version is not None:
        resolved_version_code = semver_to_code(version)
    elif header_info:
        resolved_version_code = int(header_info["version_code"])
    else:
        resolved_version_code = 1

    # Resolve epoch
    resolved_epoch: int
    if epoch is not None:
        resolved_epoch = epoch
    elif header_info:
        resolved_epoch = int(header_info["security_epoch"])
    else:
        resolved_epoch = 1

    # Resolve device_id
    resolved_device_id: str
    if device_id is not None:
        resolved_device_id = device_id
    elif header_info:
        resolved_device_id = str(header_info["device_id"])
    else:
        resolved_device_id = payload.name

    if header_info:
        console.print(
            f"[dim cyan]ℹ Auto-detected from {header_info['header_path'].name}:[/dim cyan] "
            f"[dim]Version {header_info['version_str']} (code {resolved_version_code}), "
            f"Epoch {resolved_epoch}, Device '{resolved_device_id}'[/dim]"
        )

    try:
        priv_key = load_private_key(key)
        container_bytes = pack_container(
            payload_path=payload,
            app_version=resolved_version_code,
            security_epoch=resolved_epoch,
            device_id=resolved_device_id,
            private_key=priv_key,
            out_path=out,
        )
    except (CryptoError, ContainerError, OSError, ValueError) as exc:
        console.print(f"[bold red][ERROR][/bold red] Packaging failed: {exc}")
        sys.exit(1)

    console.print(
        Panel.fit(
            f"[bold green]✓ Sealed Container Created[/bold green]\n\n"
            f"[bold]Output Package:[/bold] [yellow]{out}[/yellow] ({len(container_bytes):,} bytes)\n"
            f"[bold]Device ID:     [/bold] [cyan]{resolved_device_id}[/cyan]\n"
            f"[bold]App Version:   [/bold] [cyan]{resolved_version_code}[/cyan]\n"
            f"[bold]Security Epoch:[/bold] [magenta]{resolved_epoch}[/magenta] (Anti-rollback)\n"
            f"[bold]Payload:       [/bold] {payload.name} ({payload.stat().st_size:,} bytes)",
            title="Package Create",
            border_style="green",
        )
    )


@package_app.command("verify")
def package_verify(
    package: Annotated[Path, typer.Option("--package", "-p", help="Path to .update container.")],
    key: Annotated[Path, typer.Option("--key", "-k", help="Path to Ed25519 public key PEM file.")],
    device_id: Annotated[
        str | None,
        typer.Option("--device-id", "-d", help="Expected device ID (optional check)."),
    ] = None,
    min_epoch: Annotated[
        int,
        typer.Option("--min-epoch", "-m", help="Minimum required security epoch for anti-rollback."),
    ] = 0,
) -> None:
    """Verify digital signature, device ID, security epoch, and payload integrity of a container."""
    try:
        pub_key = load_public_key(key)
        _payload_bytes, header = unpack_and_verify(
            container_path=package,
            public_key=pub_key,
            expected_device_id=device_id,
            min_epoch=min_epoch,
        )
    except (CryptoError, ContainerError, OSError) as exc:
        console.print(f"[bold red][FAIL][/bold red] Verification failed: {exc}")
        sys.exit(1)

    console.print(
        Panel.fit(
            f"[bold green]✓ Container Verification Passed[/bold green]\n\n"
            f"[bold]Device ID:     [/bold] {header.device_id}\n"
            f"[bold]App Version:   [/bold] {header.app_version}\n"
            f"[bold]Security Epoch:[/bold] {header.security_epoch}\n"
            f"[bold]Payload:       [/bold] {header.payload_length:,} bytes (SHA-256: {header.payload_sha256_hex[:16]}...)\n"
            f"[bold]Signature:     [/bold] Valid Ed25519 ({header.signature_hex[:16]}...)",
            title="Package Verification",
            border_style="green",
        )
    )


@package_app.command("inspect")
def package_inspect(
    package: Annotated[Path, typer.Option("--package", "-p", help="Path to .update container.")],
) -> None:
    """Inspect metadata from a container header without verifying signatures."""
    try:
        header = inspect_container(package)
    except (ContainerError, OSError) as exc:
        console.print(f"[bold red][ERROR][/bold red] Inspection failed: {exc}")
        sys.exit(1)

    table = Table(title=f"Container Header: {package.name}", border_style="cyan")
    table.add_column("Field", style="bold")
    table.add_column("Value", style="yellow")

    table.add_row("Magic Bytes", str(header.magic))
    table.add_row("Header Version", str(header.header_version))
    table.add_row("App Version (Feature)", str(header.app_version))
    table.add_row("Security Epoch (Anti-Rollback)", str(header.security_epoch))
    table.add_row("Target Device ID", header.device_id)
    table.add_row("Payload Length", f"{header.payload_length:,} bytes")
    table.add_row("Payload SHA-256", header.payload_sha256_hex)
    table.add_row("Ed25519 Signature", f"{header.signature_hex[:32]}... ({len(header.signature)} bytes)")

    console.print(table)


def _render_audit_table(report: AuditReport) -> None:
    """Render a visual, formatted mitigation audit report with Rich."""
    meta_info = (
        f"[bold]Target:[/bold] {report.target_path}\n"
        f"[bold]Architecture:[/bold] {report.architecture} ({report.elf_class}-bit {report.endianness}-endian)\n"
        f"[bold]File Size:[/bold] {report.file_size:,} bytes\n"
        f"[bold]SHA-256:[/bold] {report.sha256}"
    )
    console.print(Panel(meta_info, title="[bold cyan]ELF Binary Metadata[/bold cyan]", border_style="cyan"))

    table = Table(title="Security Mitigations (checksec equivalent)", border_style="blue")
    table.add_column("Mitigation", style="bold", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("CWE", style="dim")
    table.add_column("Summary")
    table.add_column("Remediation Flag", style="yellow")

    for c in report.checks:
        if c.status == MitigationStatus.PASS:
            status_badge = "[bold green]PASS[/bold green]"
        elif c.status == MitigationStatus.FAIL:
            status_badge = "[bold red]FAIL[/bold red]"
        elif c.status == MitigationStatus.WARN:
            status_badge = "[bold yellow]WARN[/bold yellow]"
        else:
            status_badge = "[dim blue]INFO[/dim blue]"

        table.add_row(
            c.name,
            status_badge,
            c.cwe_id,
            c.summary,
            c.remediation,
        )

    console.print(table)

    score_color = "green" if report.score >= 80 else ("yellow" if report.score >= 50 else "red")
    pass_badge = "[bold green]PASSED[/bold green]" if report.passed else "[bold red]FAILED[/bold red]"
    console.print(
        Panel.fit(
            f"Hardening Score: [{score_color}]{report.score}%[/{score_color}] | Production Status: {pass_badge}",
            border_style=score_color,
        )
    )


@audit_app.command("elf")
def audit_elf(
    binary: Annotated[Path, typer.Argument(help="Path to the ELF binary to audit.")],
    format: Annotated[str, typer.Option("--format", "-f", help="Output format: 'table' or 'json'.")] = "table",
    strict: Annotated[
        bool,
        typer.Option("--strict", "-s", help="Exit with code 1 if any critical exploit mitigation fails."),
    ] = False,
    min_score: Annotated[
        int,
        typer.Option("--min-score", "-m", help="Minimum required hardening score (0-100)."),
    ] = 80,
) -> None:
    """Audit an ELF binary for security mitigations (NX, PIE, Canary, Full RELRO, Fortify, RPATH)."""
    try:
        auditor = ElfAuditor(binary)
        report = auditor.audit()
    except (FileNotFoundError, NonElfError, AuditError) as exc:
        console.print(f"[bold red][ERROR][/bold red] Audit failed: {exc}")
        sys.exit(1)

    if format.lower() == "json":
        console.print_json(report.model_dump_json(indent=2))
    else:
        _render_audit_table(report)

    failed_reasons: list[str] = []
    if strict and not report.passed:
        failed_reasons.append("Binary failed one or more critical exploit mitigations (NX, Canary, PIE, or Full RELRO)")
    if report.score < min_score:
        failed_reasons.append(f"Hardening score {report.score}% is below required threshold of {min_score}%")

    if failed_reasons:
        for reason in failed_reasons:
            console.print(f"[bold red][FAIL][/bold red] {reason}")
        sys.exit(1)
    else:
        if format.lower() != "json":
            console.print("[bold green][PASS][/bold green] Binary satisfies all mitigation requirements.")


@app.command()
def update_check() -> None:
    """Run the companion updater agent to inspect and apply pending updates."""
    from airgap_audit.companion.updater import run

    try:
        updated = run()
        if updated:
            console.print("[bold green][PASS][/bold green] Update applied successfully.")
        else:
            console.print("[dim]No update candidate or changes detected on USB drive.[/dim]")
    except (OSError, RuntimeError) as exc:
        console.print(f"[bold red][ERROR][/bold red] {exc}")
        sys.exit(1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
