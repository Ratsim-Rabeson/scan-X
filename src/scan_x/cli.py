"""Click CLI entry point for scan-X."""
from __future__ import annotations

import click


def launch_tui() -> None:
    """Launch the Textual TUI application."""
    from scan_x.app import ScanXApp

    app = ScanXApp()
    app.run()


@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx: click.Context) -> None:
    """scan-X: Terminal vulnerability search, scanning & reporting."""
    if ctx.invoked_subcommand is None:
        launch_tui()


@main.command()
def tui() -> None:
    """Launch the interactive TUI."""
    launch_tui()


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", type=click.Choice(["table", "json", "csv"]), default="table")
@click.option("--output", "-o", type=click.Path(), default=None)
def scan(path: str, fmt: str, output: str | None) -> None:
    """Scan a project directory for vulnerabilities."""
    click.echo(f"Scanning {path}... (not yet implemented)")


@main.command()
@click.argument("query")
@click.option(
    "--source",
    "-s",
    type=click.Choice(["all", "osv", "nvd", "github", "snyk"]),
    default="all",
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default=None,
)
@click.option("--limit", "-n", type=int, default=20)
def search(query: str, source: str, severity: str | None, limit: int) -> None:
    """Search vulnerabilities by keyword or CVE ID."""
    click.echo(f"Searching for '{query}'... (not yet implemented)")


@main.command()
@click.option(
    "--format", "-f", "fmt", type=click.Choice(["pdf", "html", "json", "csv"]), default="html"
)
@click.option("--output", "-o", type=click.Path(), required=True)
@click.option("--title", "-t", type=str, default="scan-X Vulnerability Report")
def report(fmt: str, output: str, title: str) -> None:
    """Generate a vulnerability report."""
    click.echo(f"Generating {fmt} report at {output}... (not yet implemented)")


@main.command()
def config() -> None:
    """Show current configuration."""
    click.echo("Configuration: (not yet implemented)")


@main.command()
def version() -> None:
    """Show scan-X version."""
    from scan_x import __version__

    click.echo(f"scan-X v{__version__}")
