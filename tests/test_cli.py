"""CLI tests. `show`-command tests inject fake repository/correlation-service
factories via monkeypatch -- no real HTTP or SQLite is ever touched, so
there are no live network calls anywhere in this file."""

from datetime import UTC, datetime

import pytest
from typer.testing import CliRunner

import vulnbrief.cli as cli
from vulnbrief.adapters.exceptions import SourceNotFoundError, SourceUnavailableError
from vulnbrief.domain.enums import SourceName, SourceOutcome
from vulnbrief.domain.models import KevInfo, SourceProvenance, VulnerabilityBriefing
from vulnbrief.storage.repository import CacheCorruptionError

runner = CliRunner()

CVE_ID = "CVE-2024-1234"
RETRIEVED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _briefing(**overrides: object) -> VulnerabilityBriefing:
    defaults: dict[str, object] = dict(
        cve_id=CVE_ID,
        description="Example vulnerability.",
        provenance=[SourceProvenance(source=SourceName.NVD, retrieved_at=RETRIEVED_AT)],
        source_outcomes={SourceName.NVD: SourceOutcome.FOUND},
        retrieved_at=RETRIEVED_AT,
    )
    defaults.update(overrides)
    return VulnerabilityBriefing(**defaults)  # type: ignore[arg-type]


class _FakeRepository:
    def __init__(
        self,
        cached: VulnerabilityBriefing | None = None,
        get_error: Exception | None = None,
        put_error: Exception | None = None,
    ) -> None:
        self.cached = cached
        self.get_error = get_error
        self.put_error = put_error
        self.put_calls: list[VulnerabilityBriefing] = []

    def get(self, cve_id: str) -> VulnerabilityBriefing | None:
        if self.get_error is not None:
            raise self.get_error
        return self.cached

    def put(self, briefing: VulnerabilityBriefing) -> None:
        self.put_calls.append(briefing)
        if self.put_error is not None:
            raise self.put_error


class _FakeCorrelationService:
    def __init__(
        self, result: VulnerabilityBriefing | None = None, error: Exception | None = None
    ) -> None:
        self.result = result
        self.error = error
        self.calls: list[str] = []

    def get_briefing(self, cve_id: str) -> VulnerabilityBriefing:
        self.calls.append(cve_id)
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


def _patch_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    repository: _FakeRepository,
    correlation: _FakeCorrelationService,
) -> None:
    monkeypatch.setattr(cli, "build_repository", lambda: repository)
    monkeypatch.setattr(cli, "build_correlation_service", lambda: correlation)


def test_help_exits_successfully() -> None:
    result = runner.invoke(cli.app, ["--help"])
    assert result.exit_code == 0


def test_help_shows_usage_and_description() -> None:
    result = runner.invoke(cli.app, ["--help"])
    assert "Usage" in result.output
    assert "vulnerability briefing" in result.output


def test_show_help_exits_successfully() -> None:
    result = runner.invoke(cli.app, ["show", "--help"])
    assert result.exit_code == 0
    assert "--refresh" in result.output


def test_show_cache_hit_does_not_call_correlation(monkeypatch: pytest.MonkeyPatch) -> None:
    repository = _FakeRepository(cached=_briefing())
    correlation = _FakeCorrelationService()
    _patch_dependencies(monkeypatch, repository, correlation)

    result = runner.invoke(cli.app, ["show", CVE_ID])

    assert result.exit_code == 0
    assert CVE_ID in result.output
    assert correlation.calls == []


def test_show_cache_miss_retrieves_fresh_and_saves(monkeypatch: pytest.MonkeyPatch) -> None:
    repository = _FakeRepository(cached=None)
    correlation = _FakeCorrelationService(result=_briefing())
    _patch_dependencies(monkeypatch, repository, correlation)

    result = runner.invoke(cli.app, ["show", CVE_ID])

    assert result.exit_code == 0
    assert correlation.calls == [CVE_ID]
    assert len(repository.put_calls) == 1


def test_show_refresh_bypasses_cached_result(monkeypatch: pytest.MonkeyPatch) -> None:
    repository = _FakeRepository(cached=_briefing(description="Stale."))
    correlation = _FakeCorrelationService(result=_briefing(description="Fresh."))
    _patch_dependencies(monkeypatch, repository, correlation)

    result = runner.invoke(cli.app, ["show", CVE_ID, "--refresh"])

    assert result.exit_code == 0
    assert "Fresh." in result.output
    assert correlation.calls == [CVE_ID]


def test_show_successful_fresh_result_is_saved(monkeypatch: pytest.MonkeyPatch) -> None:
    repository = _FakeRepository(cached=None)
    fresh = _briefing()
    correlation = _FakeCorrelationService(result=fresh)
    _patch_dependencies(monkeypatch, repository, correlation)

    runner.invoke(cli.app, ["show", CVE_ID])

    assert repository.put_calls == [fresh]


def test_show_lowercase_cve_is_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    repository = _FakeRepository(cached=_briefing())
    correlation = _FakeCorrelationService()
    _patch_dependencies(monkeypatch, repository, correlation)

    result = runner.invoke(cli.app, ["show", "cve-2024-1234"])

    assert result.exit_code == 0
    assert CVE_ID in result.output


def test_show_invalid_cve_exits_nonzero_without_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    repository = _FakeRepository()
    correlation = _FakeCorrelationService()
    _patch_dependencies(monkeypatch, repository, correlation)

    result = runner.invoke(cli.app, ["show", "not-a-cve"])

    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert "Error" in result.output


def test_show_nvd_not_found_exits_nonzero_without_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _FakeRepository(cached=None)
    correlation = _FakeCorrelationService(error=SourceNotFoundError(SourceName.NVD, "not found"))
    _patch_dependencies(monkeypatch, repository, correlation)

    result = runner.invoke(cli.app, ["show", CVE_ID])

    assert result.exit_code == 1
    assert "Traceback" not in result.output
    assert "Error" in result.output


def test_show_unrecoverable_source_failure_exits_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
    repository = _FakeRepository(cached=None)
    correlation = _FakeCorrelationService(
        error=SourceUnavailableError(SourceName.NVD, "upstream down")
    )
    _patch_dependencies(monkeypatch, repository, correlation)

    result = runner.invoke(cli.app, ["show", CVE_ID])

    assert result.exit_code == 1
    assert "Traceback" not in result.output


def test_show_partial_result_when_optional_source_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    repository = _FakeRepository(cached=None)
    partial = _briefing(
        kev=None,
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.CISA_KEV: SourceOutcome.UNAVAILABLE,
        },
    )
    correlation = _FakeCorrelationService(result=partial)
    _patch_dependencies(monkeypatch, repository, correlation)

    result = runner.invoke(cli.app, ["show", CVE_ID])

    assert result.exit_code == 0
    assert "unavailable" in result.output


def test_show_unsafe_source_text_does_not_crash_the_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    # Before Issue #24 the "[/]" raised rich.errors.MarkupError inside the
    # Console().print call, which sits outside show()'s except clauses, so the
    # user got a traceback instead of a briefing.
    unsafe = _briefing(
        kev=KevInfo(
            is_known_exploited=True,
            required_action="Apply [sic] update; see [/] bulletin\x1b[31m",
        ),
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.CISA_KEV: SourceOutcome.FOUND,
        },
    )
    repository = _FakeRepository(cached=None)
    correlation = _FakeCorrelationService(result=unsafe)
    _patch_dependencies(monkeypatch, repository, correlation)

    result = runner.invoke(cli.app, ["show", CVE_ID])

    assert result.exit_code == 0
    assert "Traceback" not in result.output
    assert "\x1b[31m" not in result.output


def test_show_cache_read_failure_self_heals(monkeypatch: pytest.MonkeyPatch) -> None:
    repository = _FakeRepository(get_error=CacheCorruptionError("corrupted"))
    correlation = _FakeCorrelationService(result=_briefing())
    _patch_dependencies(monkeypatch, repository, correlation)

    result = runner.invoke(cli.app, ["show", CVE_ID])

    assert result.exit_code == 0
    assert correlation.calls == [CVE_ID]


def test_show_cache_write_failure_after_successful_retrieval_still_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _FakeRepository(cached=None, put_error=OSError("disk full"))
    correlation = _FakeCorrelationService(result=_briefing())
    _patch_dependencies(monkeypatch, repository, correlation)

    result = runner.invoke(cli.app, ["show", CVE_ID])

    assert result.exit_code == 0
    assert CVE_ID in result.output
