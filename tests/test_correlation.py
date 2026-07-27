"""Tests for CorrelationService. Uses fake adapters implementing the
SourceAdapter protocol directly -- adapter-level HTTP behavior is already
covered by tests/adapters/, so no HTTP mocking is needed here."""

from datetime import UTC, datetime

import pytest

from vulnbrief.adapters.exceptions import (
    SourceNotFoundError,
    SourceResponseError,
    SourceTimeoutError,
    SourceUnavailableError,
)
from vulnbrief.correlation import CorrelationService
from vulnbrief.domain.enums import SourceName, SourceOutcome
from vulnbrief.domain.models import (
    CvssInfo,
    EpssInfo,
    KevInfo,
    SourceProvenance,
    VulnerabilityBriefing,
)

CVE_ID = "CVE-2024-1234"
RETRIEVED_AT = datetime(2026, 1, 1, tzinfo=UTC)


class FakeAdapter:
    """Records every CVE ID it was called with and either returns a canned
    result or raises a canned error."""

    def __init__(
        self,
        result: VulnerabilityBriefing | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.calls: list[str] = []

    def get_cve(self, cve_id: str) -> VulnerabilityBriefing:
        self.calls.append(cve_id)
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


def _nvd_briefing() -> VulnerabilityBriefing:
    return VulnerabilityBriefing(
        cve_id=CVE_ID,
        description="Example vulnerability.",
        cvss=CvssInfo(score=7.5, severity="HIGH", vector="AV:N", version="3.1"),
        provenance=[SourceProvenance(source=SourceName.NVD, retrieved_at=RETRIEVED_AT)],
        source_outcomes={SourceName.NVD: SourceOutcome.FOUND},
        retrieved_at=RETRIEVED_AT,
    )


def _kev_briefing(matched: bool) -> VulnerabilityBriefing:
    kev = (
        KevInfo(is_known_exploited=True, required_action="Patch now.")
        if matched
        else KevInfo(is_known_exploited=False)
    )
    outcome = SourceOutcome.FOUND if matched else SourceOutcome.NOT_FOUND
    return VulnerabilityBriefing(
        cve_id=CVE_ID,
        kev=kev,
        provenance=[SourceProvenance(source=SourceName.CISA_KEV, retrieved_at=RETRIEVED_AT)],
        source_outcomes={SourceName.CISA_KEV: outcome},
        retrieved_at=RETRIEVED_AT,
    )


def _epss_briefing(matched: bool) -> VulnerabilityBriefing:
    epss = EpssInfo(score=0.42, percentile=0.9) if matched else None
    outcome = SourceOutcome.FOUND if matched else SourceOutcome.NOT_FOUND
    return VulnerabilityBriefing(
        cve_id=CVE_ID,
        epss=epss,
        provenance=[SourceProvenance(source=SourceName.FIRST_EPSS, retrieved_at=RETRIEVED_AT)],
        source_outcomes={SourceName.FIRST_EPSS: outcome},
        retrieved_at=RETRIEVED_AT,
    )


def test_all_sources_successful_produces_complete_briefing() -> None:
    service = CorrelationService(
        nvd=FakeAdapter(result=_nvd_briefing()),
        kev=FakeAdapter(result=_kev_briefing(matched=True)),
        epss=FakeAdapter(result=_epss_briefing(matched=True)),
    )

    briefing = service.get_briefing(CVE_ID)

    assert briefing.description == "Example vulnerability."
    assert briefing.cvss is not None
    assert briefing.kev is not None and briefing.kev.is_known_exploited is True
    assert briefing.epss is not None and briefing.epss.score == 0.42
    assert len(briefing.provenance) == 3
    assert briefing.source_outcomes == {
        SourceName.NVD: SourceOutcome.FOUND,
        SourceName.CISA_KEV: SourceOutcome.FOUND,
        SourceName.FIRST_EPSS: SourceOutcome.FOUND,
    }


def test_kev_not_found_preserves_nvd_and_epss_data() -> None:
    service = CorrelationService(
        nvd=FakeAdapter(result=_nvd_briefing()),
        kev=FakeAdapter(result=_kev_briefing(matched=False)),
        epss=FakeAdapter(result=_epss_briefing(matched=True)),
    )

    briefing = service.get_briefing(CVE_ID)

    assert briefing.kev is not None
    assert briefing.kev.is_known_exploited is False
    assert briefing.source_outcomes[SourceName.CISA_KEV] == SourceOutcome.NOT_FOUND
    assert briefing.description == "Example vulnerability."
    assert briefing.epss is not None
    assert len(briefing.provenance) == 3  # no-match KEV still incorporated its own outcome


def test_epss_not_found_preserves_nvd_and_kev_data() -> None:
    service = CorrelationService(
        nvd=FakeAdapter(result=_nvd_briefing()),
        kev=FakeAdapter(result=_kev_briefing(matched=True)),
        epss=FakeAdapter(result=_epss_briefing(matched=False)),
    )

    briefing = service.get_briefing(CVE_ID)

    assert briefing.epss is None
    assert briefing.source_outcomes[SourceName.FIRST_EPSS] == SourceOutcome.NOT_FOUND
    assert briefing.description == "Example vulnerability."
    assert briefing.kev is not None and briefing.kev.is_known_exploited is True


def test_kev_unavailable_preserves_nvd_data_without_kev_provenance() -> None:
    service = CorrelationService(
        nvd=FakeAdapter(result=_nvd_briefing()),
        kev=FakeAdapter(error=SourceUnavailableError(SourceName.CISA_KEV, "down")),
        epss=FakeAdapter(result=_epss_briefing(matched=True)),
    )

    briefing = service.get_briefing(CVE_ID)

    assert briefing.kev is None
    assert briefing.source_outcomes[SourceName.CISA_KEV] == SourceOutcome.UNAVAILABLE
    assert briefing.description == "Example vulnerability."
    assert briefing.epss is not None
    assert len(briefing.provenance) == 2  # NVD + EPSS only, no KEV entry


def test_epss_unavailable_preserves_nvd_data_without_epss_provenance() -> None:
    service = CorrelationService(
        nvd=FakeAdapter(result=_nvd_briefing()),
        kev=FakeAdapter(result=_kev_briefing(matched=True)),
        epss=FakeAdapter(error=SourceTimeoutError(SourceName.FIRST_EPSS, "timed out")),
    )

    briefing = service.get_briefing(CVE_ID)

    assert briefing.epss is None
    assert briefing.source_outcomes[SourceName.FIRST_EPSS] == SourceOutcome.UNAVAILABLE
    assert briefing.description == "Example vulnerability."
    assert briefing.kev is not None
    assert len(briefing.provenance) == 2  # NVD + KEV only, no EPSS entry


def test_both_optional_sources_unavailable_still_returns_nvd_only_briefing() -> None:
    service = CorrelationService(
        nvd=FakeAdapter(result=_nvd_briefing()),
        kev=FakeAdapter(error=SourceUnavailableError(SourceName.CISA_KEV, "down")),
        epss=FakeAdapter(error=SourceUnavailableError(SourceName.FIRST_EPSS, "down")),
    )

    briefing = service.get_briefing(CVE_ID)

    assert briefing.kev is None
    assert briefing.epss is None
    assert briefing.description == "Example vulnerability."
    assert briefing.source_outcomes[SourceName.CISA_KEV] == SourceOutcome.UNAVAILABLE
    assert briefing.source_outcomes[SourceName.FIRST_EPSS] == SourceOutcome.UNAVAILABLE
    assert len(briefing.provenance) == 1  # NVD only


def test_malformed_optional_source_response_records_malformed_outcome() -> None:
    service = CorrelationService(
        nvd=FakeAdapter(result=_nvd_briefing()),
        kev=FakeAdapter(error=SourceResponseError(SourceName.CISA_KEV, "bad shape")),
        epss=FakeAdapter(result=_epss_briefing(matched=True)),
    )

    briefing = service.get_briefing(CVE_ID)

    assert briefing.kev is None
    assert briefing.source_outcomes[SourceName.CISA_KEV] == SourceOutcome.MALFORMED
    assert briefing.description == "Example vulnerability."


def test_nvd_not_found_propagates_and_skips_optional_sources() -> None:
    kev_adapter = FakeAdapter(result=_kev_briefing(matched=True))
    epss_adapter = FakeAdapter(result=_epss_briefing(matched=True))
    service = CorrelationService(
        nvd=FakeAdapter(error=SourceNotFoundError(SourceName.NVD, "not found")),
        kev=kev_adapter,
        epss=epss_adapter,
    )

    with pytest.raises(SourceNotFoundError):
        service.get_briefing(CVE_ID)

    assert kev_adapter.calls == []
    assert epss_adapter.calls == []


def test_nvd_timeout_propagates_and_skips_optional_sources() -> None:
    kev_adapter = FakeAdapter(result=_kev_briefing(matched=True))
    epss_adapter = FakeAdapter(result=_epss_briefing(matched=True))
    service = CorrelationService(
        nvd=FakeAdapter(error=SourceTimeoutError(SourceName.NVD, "timed out")),
        kev=kev_adapter,
        epss=epss_adapter,
    )

    with pytest.raises(SourceTimeoutError):
        service.get_briefing(CVE_ID)

    assert kev_adapter.calls == []
    assert epss_adapter.calls == []


def test_provenance_includes_entry_from_every_successful_source() -> None:
    service = CorrelationService(
        nvd=FakeAdapter(result=_nvd_briefing()),
        kev=FakeAdapter(result=_kev_briefing(matched=True)),
        epss=FakeAdapter(result=_epss_briefing(matched=True)),
    )

    briefing = service.get_briefing(CVE_ID)

    sources = {entry.source for entry in briefing.provenance}
    assert sources == {SourceName.NVD, SourceName.CISA_KEV, SourceName.FIRST_EPSS}


def test_source_outcomes_recorded_for_every_attempted_source() -> None:
    service = CorrelationService(
        nvd=FakeAdapter(result=_nvd_briefing()),
        kev=FakeAdapter(error=SourceUnavailableError(SourceName.CISA_KEV, "down")),
        epss=FakeAdapter(result=_epss_briefing(matched=False)),
    )

    briefing = service.get_briefing(CVE_ID)

    assert set(briefing.source_outcomes.keys()) == {
        SourceName.NVD,
        SourceName.CISA_KEV,
        SourceName.FIRST_EPSS,
    }


def test_retrieved_at_is_the_assembled_result_timestamp() -> None:
    service = CorrelationService(
        nvd=FakeAdapter(result=_nvd_briefing()),
        kev=FakeAdapter(result=_kev_briefing(matched=True)),
        epss=FakeAdapter(result=_epss_briefing(matched=True)),
    )

    briefing = service.get_briefing(CVE_ID)

    assert briefing.retrieved_at.tzinfo is not None
    assert briefing.retrieved_at != RETRIEVED_AT  # its own timestamp, not a source's


def test_cve_id_is_normalized_once_before_any_adapter_is_called() -> None:
    nvd_adapter = FakeAdapter(result=_nvd_briefing())
    kev_adapter = FakeAdapter(result=_kev_briefing(matched=True))
    epss_adapter = FakeAdapter(result=_epss_briefing(matched=True))
    service = CorrelationService(nvd=nvd_adapter, kev=kev_adapter, epss=epss_adapter)

    service.get_briefing("cve-2024-1234")

    assert nvd_adapter.calls == ["CVE-2024-1234"]
    assert kev_adapter.calls == ["CVE-2024-1234"]
    assert epss_adapter.calls == ["CVE-2024-1234"]


def test_no_live_network_calls_are_made_at_this_layer() -> None:
    # Fake adapters never touch HTTP; this is a structural guarantee of the
    # test doubles themselves rather than something to assert at runtime.
    service = CorrelationService(
        nvd=FakeAdapter(result=_nvd_briefing()),
        kev=FakeAdapter(result=_kev_briefing(matched=True)),
        epss=FakeAdapter(result=_epss_briefing(matched=True)),
    )
    service.get_briefing(CVE_ID)


def test_unexpected_non_source_error_from_optional_adapter_propagates() -> None:
    service = CorrelationService(
        nvd=FakeAdapter(result=_nvd_briefing()),
        kev=FakeAdapter(error=RuntimeError("bug, not an expected source failure")),
        epss=FakeAdapter(result=_epss_briefing(matched=True)),
    )

    with pytest.raises(RuntimeError):
        service.get_briefing(CVE_ID)
