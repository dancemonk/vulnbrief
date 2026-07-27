"""Tests for render_briefing -- pure string output, no I/O."""

from datetime import UTC, datetime

from vulnbrief.domain.enums import SourceName, SourceOutcome
from vulnbrief.domain.models import (
    CvssInfo,
    EpssInfo,
    KevInfo,
    Reference,
    SourceProvenance,
    VulnerabilityBriefing,
)
from vulnbrief.rendering import render_briefing

CVE_ID = "CVE-2024-1234"
RETRIEVED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _base_briefing(**overrides: object) -> VulnerabilityBriefing:
    defaults: dict[str, object] = dict(
        cve_id=CVE_ID,
        provenance=[SourceProvenance(source=SourceName.NVD, retrieved_at=RETRIEVED_AT)],
        source_outcomes={SourceName.NVD: SourceOutcome.FOUND},
        retrieved_at=RETRIEVED_AT,
    )
    defaults.update(overrides)
    return VulnerabilityBriefing(**defaults)  # type: ignore[arg-type]


def test_full_briefing_renders_all_sections() -> None:
    briefing = _base_briefing(
        description="Example vulnerability.",
        cvss=CvssInfo(score=7.5, severity="HIGH", vector="AV:N"),
        epss=EpssInfo(score=0.42, percentile=0.9),
        kev=KevInfo(is_known_exploited=True, required_action="Patch now."),
        references=[Reference(url="https://example.com/advisory")],
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.CISA_KEV: SourceOutcome.FOUND,
            SourceName.FIRST_EPSS: SourceOutcome.FOUND,
        },
    )

    output = render_briefing(briefing)

    assert CVE_ID in output
    assert "Example vulnerability." in output
    assert "7.5" in output
    assert "0.42" in output
    assert "known exploited" in output
    assert "https://example.com/advisory" in output


def test_kev_not_found_differs_from_kev_unavailable() -> None:
    not_found = _base_briefing(
        kev=None,
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.CISA_KEV: SourceOutcome.NOT_FOUND,
        },
    )
    unavailable = _base_briefing(
        kev=None,
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.CISA_KEV: SourceOutcome.UNAVAILABLE,
        },
    )

    not_found_output = render_briefing(not_found)
    unavailable_output = render_briefing(unavailable)

    assert "not in catalog" in not_found_output
    assert "unavailable" in unavailable_output
    assert not_found_output != unavailable_output


def test_epss_absent_due_to_failure_differs_from_zero_score() -> None:
    failed = _base_briefing(
        epss=None,
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.FIRST_EPSS: SourceOutcome.UNAVAILABLE,
        },
    )
    zero_score = _base_briefing(
        epss=EpssInfo(score=0.0, percentile=0.0),
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.FIRST_EPSS: SourceOutcome.FOUND,
        },
    )

    failed_output = render_briefing(failed)
    zero_output = render_briefing(zero_score)

    assert "unavailable" in failed_output
    assert "0.0" in zero_output
    assert failed_output != zero_output
