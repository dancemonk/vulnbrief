"""VulnBrief command-line interface.

This module validates input and delegates; it must not perform HTTP requests
or parse source-specific data (see docs/architecture.md). `show`'s actual
retrieval/cache/save logic lives in `vulnbrief.workflow`, testable without
Typer; this module only wires real dependencies, maps typed errors to exit
codes, and prints the rendered result.
"""

import os
from pathlib import Path

import typer
from rich.console import Console

from vulnbrief.adapters import EpssAdapter, KevAdapter, NvdAdapter
from vulnbrief.adapters.exceptions import SourceError
from vulnbrief.correlation import CorrelationService
from vulnbrief.rendering import build_renderable
from vulnbrief.storage import (
    BriefingRepository,
    CacheError,
    NullBriefingRepository,
    SqliteBriefingRepository,
)
from vulnbrief.workflow import run_show

DEFAULT_DB_PATH = Path.home() / ".vulnbrief" / "cache.db"

app = typer.Typer(
    name="vulnbrief",
    help="Retrieve an explainable vulnerability briefing for one CVE.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)


@app.callback()
def main() -> None:
    """VulnBrief: terminal vulnerability briefing tool."""


def build_repository() -> SqliteBriefingRepository:
    db_path = os.environ.get("VULNBRIEF_DB_PATH", str(DEFAULT_DB_PATH))
    return SqliteBriefingRepository(db_path)


def build_correlation_service() -> CorrelationService:
    return CorrelationService(nvd=NvdAdapter(), kev=KevAdapter(), epss=EpssAdapter())


@app.command()
def show(
    cve_id: str = typer.Argument(..., help="CVE identifier, e.g. CVE-2024-1234"),
    refresh: bool = typer.Option(False, "--refresh", help="Bypass cached data and refetch."),
) -> None:
    """Display an explainable vulnerability briefing for one CVE."""

    def warn(message: str) -> None:
        typer.echo(f"Warning: {message}", err=True)

    # An unusable cache degrades the lookup instead of blocking it: sources are
    # still queried, results simply are not cached this run.
    repository: BriefingRepository
    try:
        repository = build_repository()
    except CacheError as exc:
        warn(f"{exc}. Continuing without cache.")
        repository = NullBriefingRepository()

    try:
        briefing = run_show(
            cve_id, refresh, repository, build_correlation_service(), on_warning=warn
        )
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None
    except SourceError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from None
    except CacheError as exc:
        # Defensive: run_show absorbs cache failures itself, so reaching here
        # means a repository raised outside the paths it guards.
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from None

    Console().print(build_renderable(briefing))


if __name__ == "__main__":
    app()
