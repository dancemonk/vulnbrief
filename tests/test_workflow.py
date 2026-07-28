"""Tests for run_show. Uses fake repository/correlation service -- no
HTTP, no SQLite, no live network calls."""

from datetime import UTC, datetime

import pytest

from vulnbrief.adapters.exceptions import SourceNotFoundError
from vulnbrief.domain.enums import SourceName, SourceOutcome
from vulnbrief.domain.models import SourceProvenance, VulnerabilityBriefing
from vulnbrief.storage.repository import CacheCorruptionError, CacheUnavailableError
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


def _cached_with_outcomes(
    outcomes: dict[SourceName, SourceOutcome], description: str = "Cached value."
) -> VulnerabilityBriefing:
    return VulnerabilityBriefing(
        cve_id=CVE_ID,
        description=description,
        provenance=[SourceProvenance(source=SourceName.NVD, retrieved_at=RETRIEVED_AT)],
        source_outcomes=outcomes,
        retrieved_at=RETRIEVED_AT,
    )


def test_cached_unavailable_optional_source_triggers_fresh_retrieval() -> None:
    # A briefing cached during a transient CISA outage must not be served
    # forever; there is no TTL to age it out.
    stale = _cached_with_outcomes(
        {SourceName.NVD: SourceOutcome.FOUND, SourceName.CISA_KEV: SourceOutcome.UNAVAILABLE},
        description="Cached during KEV outage.",
    )
    repository = FakeRepository(cached=stale)
    fresh = _briefing(description="Fresh with KEV data.")
    correlation = FakeCorrelationService(result=fresh)

    result = run_show(CVE_ID, refresh=False, repository=repository, correlation_service=correlation)

    assert result.description == "Fresh with KEV data."
    assert correlation.calls == [CVE_ID]
    assert repository.put_calls == [fresh]


def test_cached_malformed_optional_source_triggers_fresh_retrieval() -> None:
    stale = _cached_with_outcomes(
        {SourceName.NVD: SourceOutcome.FOUND, SourceName.FIRST_EPSS: SourceOutcome.MALFORMED},
        description="Cached with malformed EPSS.",
    )
    repository = FakeRepository(cached=stale)
    fresh = _briefing(description="Fresh with EPSS data.")
    correlation = FakeCorrelationService(result=fresh)

    result = run_show(CVE_ID, refresh=False, repository=repository, correlation_service=correlation)

    assert result.description == "Fresh with EPSS data."
    assert correlation.calls == [CVE_ID]


def test_cached_not_found_outcome_remains_a_usable_cache_hit() -> None:
    # NOT_FOUND is a settled answer, not a failure: the source was reached and
    # genuinely had no entry, so the cached briefing stays valid.
    cached = _cached_with_outcomes(
        {
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.CISA_KEV: SourceOutcome.NOT_FOUND,
            SourceName.FIRST_EPSS: SourceOutcome.NOT_FOUND,
        },
        description="Complete with no-match enrichment.",
    )
    repository = FakeRepository(cached=cached)
    correlation = FakeCorrelationService()

    result = run_show(CVE_ID, refresh=False, repository=repository, correlation_service=correlation)

    assert result.description == "Complete with no-match enrichment."
    assert correlation.calls == []
    assert repository.put_calls == []


def test_cache_write_failure_returns_result_and_emits_one_warning() -> None:
    repository = FakeRepository(cached=None, put_error=CacheUnavailableError("disk full"))
    fresh = _briefing()
    correlation = FakeCorrelationService(result=fresh)
    warnings: list[str] = []

    result = run_show(
        CVE_ID,
        refresh=False,
        repository=repository,
        correlation_service=correlation,
        on_warning=warnings.append,
    )

    assert result.description == fresh.description
    assert len(warnings) == 1
    assert "cache" in warnings[0]


def test_unreadable_cache_falls_through_and_warns_once() -> None:
    # Issue #26 originally asserted silence here, reasoning that the fresh
    # lookup made the read failure unremarkable. Issue #34 reversed that: a
    # silently degraded cache is how a permanently broken one stays invisible.
    repository = FakeRepository(get_error=CacheUnavailableError("cache unreadable"))
    fresh = _briefing(description="Fresh after unreadable cache.")
    correlation = FakeCorrelationService(result=fresh)
    warnings: list[str] = []

    result = run_show(
        CVE_ID,
        refresh=False,
        repository=repository,
        correlation_service=correlation,
        on_warning=warnings.append,
    )

    assert result.description == "Fresh after unreadable cache."
    assert correlation.calls == [CVE_ID]
    assert len(warnings) == 1
    assert "cached data" in warnings[0]


def test_corrupt_cached_record_falls_through_and_warns_once() -> None:
    repository = FakeRepository(get_error=CacheCorruptionError("corrupted row"))
    fresh = _briefing(description="Fresh after corruption.")
    correlation = FakeCorrelationService(result=fresh)
    warnings: list[str] = []

    result = run_show(
        CVE_ID,
        refresh=False,
        repository=repository,
        correlation_service=correlation,
        on_warning=warnings.append,
    )

    assert result.description == "Fresh after corruption."
    assert len(warnings) == 1


def test_cache_read_warning_exposes_no_sqlite_or_path_details() -> None:
    error = CacheUnavailableError("cache database could not be read")
    repository = FakeRepository(get_error=error)
    correlation = FakeCorrelationService(result=_briefing())
    warnings: list[str] = []

    run_show(
        CVE_ID,
        refresh=False,
        repository=repository,
        correlation_service=correlation,
        on_warning=warnings.append,
    )

    assert len(warnings) == 1
    assert "sqlite" not in warnings[0].lower()
    assert "/" not in warnings[0]
