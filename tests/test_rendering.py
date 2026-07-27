"""Tests for the Rich briefing renderer. All rendering happens through an
in-memory Console (render_briefing_text) -- no terminal, no I/O, no
networking or storage of any kind is touched by this module."""

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
from vulnbrief.rendering import build_renderable, render_briefing_text

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


def test_complete_briefing_renders_all_fields() -> None:
    briefing = _base_briefing(
        description="Example vulnerability description.",
        published_at=datetime(2024, 1, 1, tzinfo=UTC),
        modified_at=datetime(2024, 2, 1, tzinfo=UTC),
        cvss=CvssInfo(score=7.5, severity="HIGH", vector="AV:N/AC:L"),
        epss=EpssInfo(score=0.42, percentile=0.9),
        kev=KevInfo(is_known_exploited=True, required_action="Patch now.", due_date=None),
        references=[Reference(url="https://example.com/advisory")],
        provenance=[
            SourceProvenance(source=SourceName.NVD, retrieved_at=RETRIEVED_AT),
            SourceProvenance(source=SourceName.CISA_KEV, retrieved_at=RETRIEVED_AT),
            SourceProvenance(source=SourceName.FIRST_EPSS, retrieved_at=RETRIEVED_AT),
        ],
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.CISA_KEV: SourceOutcome.FOUND,
            SourceName.FIRST_EPSS: SourceOutcome.FOUND,
        },
    )

    output = render_briefing_text(briefing)

    assert CVE_ID in output
    assert "Example vulnerability description." in output
    assert "2024-01-01" in output and "2024-02-01" in output
    assert "7.5" in output
    assert "HIGH" in output
    assert "0.42" in output
    assert "Known Exploited" in output
    assert "Patch now." in output
    assert "https://example.com/advisory" in output
    assert "NVD" in output and "CISA KEV" in output and "FIRST EPSS" in output


def test_missing_cvss_shows_no_data_available() -> None:
    briefing = _base_briefing(cvss=None)

    output = render_briefing_text(briefing)

    assert "no data available" in output


def test_missing_epss_due_to_no_match_shows_no_data_available() -> None:
    briefing = _base_briefing(
        epss=None,
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.FIRST_EPSS: SourceOutcome.NOT_FOUND,
        },
    )

    output = render_briefing_text(briefing)

    assert "no data available" in output


def test_kev_positive_result_shows_known_exploited() -> None:
    briefing = _base_briefing(
        kev=KevInfo(is_known_exploited=True),
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.CISA_KEV: SourceOutcome.FOUND,
        },
    )

    output = render_briefing_text(briefing)

    assert "Known Exploited" in output


def test_kev_negative_result_shows_not_in_catalog() -> None:
    briefing = _base_briefing(
        kev=KevInfo(is_known_exploited=False),
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.CISA_KEV: SourceOutcome.NOT_FOUND,
        },
    )

    output = render_briefing_text(briefing)

    assert "Not in KEV catalog" in output


def test_kev_unknown_due_to_source_failure_is_distinct_from_negative_result() -> None:
    negative = _base_briefing(
        kev=None,
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.CISA_KEV: SourceOutcome.NOT_FOUND,
        },
    )
    failed = _base_briefing(
        kev=None,
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.CISA_KEV: SourceOutcome.UNAVAILABLE,
        },
    )

    negative_output = render_briefing_text(negative)
    failed_output = render_briefing_text(failed)

    assert "Not in KEV catalog" in negative_output
    assert "KEV status unavailable" in failed_output
    assert negative_output != failed_output


def test_incomplete_optional_metadata_renders_without_crashing() -> None:
    briefing = _base_briefing(
        description=None,
        published_at=None,
        modified_at=None,
        cvss=CvssInfo(score=None, severity=None, vector=None, version=None),
        epss=None,
        kev=KevInfo(is_known_exploited=True, required_action=None, due_date=None),
        references=[],
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.CISA_KEV: SourceOutcome.FOUND,
            SourceName.FIRST_EPSS: SourceOutcome.UNAVAILABLE,
        },
    )

    output = render_briefing_text(briefing)

    assert "unknown" in output
    assert "no data available" in output
    assert "unavailable" in output
    assert "Known Exploited" in output


def test_source_provenance_shown_for_every_attempted_source() -> None:
    briefing = _base_briefing(
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.CISA_KEV: SourceOutcome.UNAVAILABLE,
            SourceName.FIRST_EPSS: SourceOutcome.NOT_FOUND,
        },
    )

    output = render_briefing_text(briefing)

    assert "NVD" in output
    assert "CISA KEV" in output
    assert "FIRST EPSS" in output
    assert "Found" in output
    assert "Unavailable" in output
    assert "Not Found" in output
    assert "—" in output  # KEV/EPSS have no provenance entry (not incorporated)


def test_long_description_renders_without_crashing_at_narrow_width() -> None:
    long_description = "Example vulnerability. " * 40
    briefing = _base_briefing(description=long_description)

    output = render_briefing_text(briefing, width=20)

    assert "Example" in output


def test_narrow_terminal_width_renders_complete_briefing_without_crashing() -> None:
    briefing = _base_briefing(
        description="A reasonably long description of the vulnerability.",
        cvss=CvssInfo(score=7.5, severity="HIGH", vector="AV:N/AC:L"),
        epss=EpssInfo(score=0.42, percentile=0.9),
        kev=KevInfo(is_known_exploited=True, required_action="Patch now."),
        references=[Reference(url="https://example.com/advisory")],
    )

    output = render_briefing_text(briefing, width=20)

    assert CVE_ID in output


def test_no_color_output_contains_no_ansi_escape_codes() -> None:
    briefing = _base_briefing(
        cvss=CvssInfo(score=7.5, severity="HIGH"),
        kev=KevInfo(is_known_exploited=True),
    )

    output = render_briefing_text(briefing, no_color=True)

    assert "\x1b[" not in output


def test_renderer_performs_no_networking_or_storage_operations() -> None:
    # build_renderable takes only a VulnerabilityBriefing and returns Rich
    # objects -- there is no adapter, HTTPX, or SQLite import anywhere in
    # vulnbrief.rendering for it to call, so this is a structural guarantee
    # rather than something to mock and assert at runtime.
    import vulnbrief.rendering as rendering_module

    source = rendering_module.__file__
    assert source is not None
    with open(source) as f:
        import_lines = [
            line for line in f if line.startswith("import ") or line.startswith("from ")
        ]
    assert not any("httpx" in line for line in import_lines)
    assert not any("sqlite3" in line for line in import_lines)
    assert not any("vulnbrief.adapters" in line for line in import_lines)
    assert not any("vulnbrief.storage" in line for line in import_lines)

    briefing = _base_briefing()
    renderable = build_renderable(briefing)
    assert renderable is not None
