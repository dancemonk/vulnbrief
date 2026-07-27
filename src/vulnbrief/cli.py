"""VulnBrief command-line interface.

This module wires the Typer application only. It must not perform HTTP
requests or parse source-specific data (see docs/architecture.md); command
logic is added by later, scoped issues (e.g. `show`, Issue #9).
"""

import typer

app = typer.Typer(
    name="vulnbrief",
    help="Retrieve an explainable vulnerability briefing for one CVE.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def main() -> None:
    """VulnBrief: terminal vulnerability briefing tool."""


if __name__ == "__main__":
    app()
