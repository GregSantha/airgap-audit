"""Command-line interface for airgap-audit."""

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

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
    device_id: Annotated[str, typer.Option("--device-id", "-d", help="Target hardware device identifier.")],
    key: Annotated[Path, typer.Option("--key", "-k", help="Path to Ed25519 private key PEM file.")],
    out: Annotated[Path, typer.Option("--out", "-o", help="Output .update container filepath.")],
    version: Annotated[int, typer.Option("--version", "-v", help="Application feature version number (e.g. 1).")] = 1,
    epoch: Annotated[
        int,
        typer.Option("--epoch", "-e", help="Security epoch for anti-rollback protection (default: 1)."),
    ] = 1,
) -> None:
    """Pack and sign an ELF binary into a sealed .update container with dual-versioning."""
    try:
        priv_key = load_private_key(key)
        container_bytes = pack_container(
            payload_path=payload,
            app_version=version,
            security_epoch=epoch,
            device_id=device_id,
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
            f"[bold]Device ID:     [/bold] [cyan]{device_id}[/cyan]\n"
            f"[bold]App Version:   [/bold] [cyan]{version}[/cyan] (Feature version)\n"
            f"[bold]Security Epoch:[/bold] [magenta]{epoch}[/magenta] (Anti-rollback index)\n"
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
