"""Validation tests for normalized vulnerability domain models."""

from datetime import UTC, date, datetime

import pytest
from pydantic import ValidationError

from vulnbrief.domain.enums import SourceName, SourceOutcome
from vulnbrief.domain.models import (
    CvssInfo,
    EpssInfo,
    KevInfo,
    Reference,
    SourceProvenance,
    VulnerabilityBriefing,
)

RETRIEVED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def test_complete_briefing_constructs() -> None:
    briefing = VulnerabilityBriefing(
        cve_id="CVE-2024-1234",
        description="Example vulnerability.",
        published_at=datetime(2024, 1, 1, tzinfo=UTC),
        modified_at=datetime(2024, 2, 1, tzinfo=UTC),
        cvss=CvssInfo(score=7.5, severity="HIGH", vector="AV:N/AC:L", version="3.1"),
        epss=EpssInfo(score=0.42, percentile=0.9, data_date=date(2024, 1, 2)),
        kev=KevInfo(is_known_exploited=True, date_added=date(2024, 1, 3)),
        references=[Reference(url="https://example.com/advisory")],
        provenance=[
            SourceProvenance(source=SourceName.NVD, retrieved_at=RETRIEVED_AT),
        ],
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.CISA_KEV: SourceOutcome.FOUND,
            SourceName.FIRST_EPSS: SourceOutcome.FOUND,
        },
        retrieved_at=RETRIEVED_AT,
    )
    assert briefing.cve_id == "CVE-2024-1234"
    assert briefing.cvss is not None and briefing.cvss.score == 7.5


def test_missing_optional_fields_default_to_none_or_empty() -> None:
    briefing = VulnerabilityBriefing(cve_id="CVE-2024-1234", retrieved_at=RETRIEVED_AT)
    assert briefing.description is None
    assert briefing.published_at is None
    assert briefing.cvss is None
    assert briefing.epss is None
    assert briefing.kev is None
    assert briefing.references == []
    assert briefing.provenance == []
    assert briefing.source_outcomes == {}


def test_zero_epss_score_is_preserved_and_distinct_from_none() -> None:
    briefing_with_zero = VulnerabilityBriefing(
        cve_id="CVE-2024-1234",
        epss=EpssInfo(score=0.0, percentile=0.0),
        retrieved_at=RETRIEVED_AT,
    )
    briefing_without_epss = VulnerabilityBriefing(cve_id="CVE-2024-1234", retrieved_at=RETRIEVED_AT)
    assert briefing_with_zero.epss is not None
    assert briefing_with_zero.epss.score == 0.0
    assert briefing_without_epss.epss is None


def test_false_kev_status_is_preserved_and_distinct_from_none() -> None:
    briefing_not_exploited = VulnerabilityBriefing(
        cve_id="CVE-2024-1234",
        kev=KevInfo(is_known_exploited=False),
        retrieved_at=RETRIEVED_AT,
    )
    briefing_without_kev = VulnerabilityBriefing(cve_id="CVE-2024-1234", retrieved_at=RETRIEVED_AT)
    assert briefing_not_exploited.kev is not None
    assert briefing_not_exploited.kev.is_known_exploited is False
    assert briefing_without_kev.kev is None


@pytest.mark.parametrize("score", [-0.1, 1.5])
def test_epss_rejects_out_of_range_score(score: float) -> None:
    with pytest.raises(ValidationError):
        EpssInfo(score=score, percentile=0.5)


@pytest.mark.parametrize("percentile", [-0.1, 1.5])
def test_epss_rejects_out_of_range_percentile(percentile: float) -> None:
    with pytest.raises(ValidationError):
        EpssInfo(score=0.5, percentile=percentile)


@pytest.mark.parametrize("score", [-1.0, 10.1])
def test_cvss_rejects_out_of_range_score(score: float) -> None:
    with pytest.raises(ValidationError):
        CvssInfo(score=score)


def test_source_outcomes_track_each_source_independently() -> None:
    briefing = VulnerabilityBriefing(
        cve_id="CVE-2024-1234",
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.FIRST_EPSS: SourceOutcome.NOT_FOUND,
            SourceName.CISA_KEV: SourceOutcome.UNAVAILABLE,
        },
        retrieved_at=RETRIEVED_AT,
    )
    assert briefing.source_outcomes[SourceName.NVD] == SourceOutcome.FOUND
    assert briefing.source_outcomes[SourceName.FIRST_EPSS] == SourceOutcome.NOT_FOUND
    assert briefing.source_outcomes[SourceName.CISA_KEV] == SourceOutcome.UNAVAILABLE


def test_retrieved_at_requires_timezone_aware_datetime() -> None:
    with pytest.raises(ValidationError):
        VulnerabilityBriefing(cve_id="CVE-2024-1234", retrieved_at=datetime(2026, 1, 1))


def test_source_provenance_requires_timezone_aware_datetime() -> None:
    with pytest.raises(ValidationError):
        SourceProvenance(source=SourceName.NVD, retrieved_at=datetime(2026, 1, 1))


def test_cve_id_normalizes_lowercase_input() -> None:
    briefing = VulnerabilityBriefing(cve_id="cve-2024-1234", retrieved_at=RETRIEVED_AT)
    assert briefing.cve_id == "CVE-2024-1234"


def test_cve_id_rejects_malformed_input() -> None:
    with pytest.raises(ValidationError):
        VulnerabilityBriefing(cve_id="not-a-cve", retrieved_at=RETRIEVED_AT)


def test_extra_fields_are_forbidden() -> None:
    with pytest.raises(ValidationError):
        VulnerabilityBriefing.model_validate(
            {
                "cve_id": "CVE-2024-1234",
                "retrieved_at": RETRIEVED_AT,
                "unexpected_field": "value",
            }
        )
