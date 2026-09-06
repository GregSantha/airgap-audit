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
