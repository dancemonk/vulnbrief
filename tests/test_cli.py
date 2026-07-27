"""CLI smoke tests for the empty VulnBrief app (Issue #2)."""

from typer.testing import CliRunner

from vulnbrief.cli import app

runner = CliRunner()


def test_help_exits_successfully() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0


def test_help_shows_usage_and_description() -> None:
    result = runner.invoke(app, ["--help"])
    assert "Usage" in result.output
    assert "vulnerability briefing" in result.output
