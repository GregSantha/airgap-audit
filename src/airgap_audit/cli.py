"""Command-line interface for airgap-audit."""

import sys

import typer
from rich.console import Console

app = typer.Typer(
    name="airgap-audit",
    help="Offline USB update manager & binary security auditor for embedded Linux applications.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def version() -> None:
    """Print the airgap-audit version."""
    from airgap_audit import __version__

    console.print(f"[bold cyan]airgap-audit[/bold cyan] version [green]{__version__}[/green]")


@app.command()
def update_check(
    usb_mount: str = typer.Option("/media/usb", help="Path to mounted USB pendrive"),
    target: str = typer.Option("/usr/local/bin/lvgl_gui", help="Path to destination executable"),
    pubkey: str = typer.Option("/etc/airgap-audit/pubkey.pem", help="Path to trusted public key"),
) -> None:
    """Run the companion updater agent to inspect and apply pending updates."""
    from pathlib import Path

    from airgap_audit.companion.updater import run_update

    try:
        updated = run_update(
            usb_mount=Path(usb_mount),
            target_binary=Path(target),
            pubkey_path=Path(pubkey),
        )
        if updated:
            console.print("[bold green][PASS][/bold green] Update applied successfully.")
        else:
            console.print("[dim]No update bundle detected on USB drive.[/dim]")
    except NotImplementedError as exc:
        console.print(f"[bold yellow][STUB][/bold yellow] {exc}")
        sys.exit(0)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
