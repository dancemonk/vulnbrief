"""Tests for run_show. Uses fake repository/correlation service -- no
HTTP, no SQLite, no live network calls."""

from datetime import UTC, datetime

import pytest

from vulnbrief.adapters.exceptions import SourceNotFoundError
from vulnbrief.domain.enums import SourceName, SourceOutcome
from vulnbrief.domain.models import SourceProvenance, VulnerabilityBriefing
from vulnbrief.storage.repository import CacheCorruptionError
from vulnbrief.workflow import run_show

CVE_ID = "CVE-2024-1234"
RETRIEVED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _briefing(description: str = "Example vulnerability.") -> VulnerabilityBriefing:
    return VulnerabilityBriefing(
        cve_id=CVE_ID,
        description=description,
        provenance=[SourceProvenance(source=SourceName.NVD, retrieved_at=RETRIEVED_AT)],
        source_outcomes={SourceName.NVD: SourceOutcome.FOUND},
        retrieved_at=RETRIEVED_AT,
    )


class FakeRepository:
    def __init__(
        self,
        cached: VulnerabilityBriefing | None = None,
        get_error: Exception | None = None,
        put_error: Exception | None = None,
    ) -> None:
        self.cached = cached
        self.get_error = get_error
        self.put_error = put_error
        self.get_calls: list[str] = []
        self.put_calls: list[VulnerabilityBriefing] = []

    def get(self, cve_id: str) -> VulnerabilityBriefing | None:
        self.get_calls.append(cve_id)
        if self.get_error is not None:
            raise self.get_error
        return self.cached

    def put(self, briefing: VulnerabilityBriefing) -> None:
        self.put_calls.append(briefing)
        if self.put_error is not None:
            raise self.put_error


class FakeCorrelationService:
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


def test_cache_hit_returns_cached_briefing_without_calling_correlation() -> None:
    repository = FakeRepository(cached=_briefing())
    correlation = FakeCorrelationService()

    result = run_show(CVE_ID, refresh=False, repository=repository, correlation_service=correlation)

    assert result.description == "Example vulnerability."
    assert correlation.calls == []
    assert repository.put_calls == []


def test_cache_miss_calls_correlation_and_saves_result() -> None:
    repository = FakeRepository(cached=None)
    fresh = _briefing(description="Fresh from sources.")
    correlation = FakeCorrelationService(result=fresh)

    result = run_show(CVE_ID, refresh=False, repository=repository, correlation_service=correlation)

    assert result.description == "Fresh from sources."
    assert correlation.calls == [CVE_ID]
    assert repository.put_calls == [fresh]


def test_refresh_bypasses_cache_even_when_valid_entry_exists() -> None:
    repository = FakeRepository(cached=_briefing(description="Stale cached value."))
    fresh = _briefing(description="Fresh from sources.")
    correlation = FakeCorrelationService(result=fresh)

    result = run_show(CVE_ID, refresh=True, repository=repository, correlation_service=correlation)

    assert result.description == "Fresh from sources."
    assert repository.get_calls == []
    assert correlation.calls == [CVE_ID]
    assert repository.put_calls == [fresh]


def test_successful_fresh_result_is_saved_to_cache() -> None:
    repository = FakeRepository(cached=None)
    fresh = _briefing()
    correlation = FakeCorrelationService(result=fresh)

    run_show(CVE_ID, refresh=False, repository=repository, correlation_service=correlation)

    assert repository.put_calls == [fresh]


def test_lowercase_cve_id_is_normalized_before_any_call() -> None:
    repository = FakeRepository(cached=_briefing())
    correlation = FakeCorrelationService()

    run_show("cve-2024-1234", refresh=False, repository=repository, correlation_service=correlation)

    assert repository.get_calls == [CVE_ID]


def test_invalid_cve_id_raises_before_touching_repository_or_correlation() -> None:
    repository = FakeRepository()
    correlation = FakeCorrelationService()

    with pytest.raises(ValueError):
        run_show("not-a-cve", refresh=False, repository=repository, correlation_service=correlation)

    assert repository.get_calls == []
    assert correlation.calls == []


def test_nvd_not_found_propagates_and_saves_nothing() -> None:
    repository = FakeRepository(cached=None)
    correlation = FakeCorrelationService(error=SourceNotFoundError(SourceName.NVD, "not found"))

    with pytest.raises(SourceNotFoundError):
        run_show(CVE_ID, refresh=False, repository=repository, correlation_service=correlation)

    assert repository.put_calls == []


def test_partial_result_from_optional_source_failure_is_still_saved() -> None:
    # CorrelationService itself already absorbs KEV/EPSS failures into a
    # partial-but-successful VulnerabilityBriefing (see #7); run_show treats
    # any returned briefing as a success regardless of partial enrichment.
    repository = FakeRepository(cached=None)
    partial = VulnerabilityBriefing(
        cve_id=CVE_ID,
        description="NVD data present.",
        provenance=[SourceProvenance(source=SourceName.NVD, retrieved_at=RETRIEVED_AT)],
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.CISA_KEV: SourceOutcome.UNAVAILABLE,
            SourceName.FIRST_EPSS: SourceOutcome.UNAVAILABLE,
        },
        retrieved_at=RETRIEVED_AT,
    )
    correlation = FakeCorrelationService(result=partial)

    result = run_show(CVE_ID, refresh=False, repository=repository, correlation_service=correlation)

    assert result.kev is None
    assert result.source_outcomes[SourceName.CISA_KEV] == SourceOutcome.UNAVAILABLE
    assert repository.put_calls == [partial]


def test_cache_read_failure_falls_through_to_fresh_retrieval() -> None:
    repository = FakeRepository(get_error=CacheCorruptionError("corrupted row"))
    fresh = _briefing(description="Fresh after corruption.")
    correlation = FakeCorrelationService(result=fresh)

    result = run_show(CVE_ID, refresh=False, repository=repository, correlation_service=correlation)

    assert result.description == "Fresh after corruption."
    assert correlation.calls == [CVE_ID]
    assert repository.put_calls == [fresh]  # heals the corrupted row


def test_cache_write_failure_after_successful_retrieval_does_not_raise() -> None:
    repository = FakeRepository(cached=None, put_error=OSError("disk full"))
    fresh = _briefing()
    correlation = FakeCorrelationService(result=fresh)

    result = run_show(CVE_ID, refresh=False, repository=repository, correlation_service=correlation)

    assert result.description == fresh.description
