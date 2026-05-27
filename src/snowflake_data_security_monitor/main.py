"""Command-line entry point placeholder."""

from __future__ import annotations

import typer

app = typer.Typer(help="Snowflake data security posture monitor.")


@app.command()
def scan() -> None:
    """Placeholder command for the future scanner workflow."""
    typer.echo("Scanner implementation is not available in the foundation scaffold.")


if __name__ == "__main__":
    app()
