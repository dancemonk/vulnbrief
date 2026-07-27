"""Plain-text rendering of a normalized vulnerability briefing.

Basic readable output only -- advanced Rich card styling is Issue #10.
Accesses no adapter, HTTP client, or storage implementation (V4).
"""

from vulnbrief.domain.enums import SourceName, SourceOutcome
from vulnbrief.domain.models import VulnerabilityBriefing

_SOURCE_LABELS = {
    SourceName.NVD: "NVD",
    SourceName.CISA_KEV: "CISA KEV",
    SourceName.FIRST_EPSS: "FIRST EPSS",
}


def render_briefing(briefing: VulnerabilityBriefing) -> str:
    lines = [briefing.cve_id]

    if briefing.description:
        lines.append(briefing.description)

    if briefing.published_at or briefing.modified_at:
        published = briefing.published_at.isoformat() if briefing.published_at else "unknown"
        modified = briefing.modified_at.isoformat() if briefing.modified_at else "unknown"
        lines.append(f"Published: {published}  Modified: {modified}")

    if briefing.cvss is not None:
        parts = [
            p
            for p in (
                f"score {briefing.cvss.score}" if briefing.cvss.score is not None else None,
                briefing.cvss.severity,
                briefing.cvss.vector,
            )
            if p
        ]
        lines.append("CVSS: " + (", ".join(parts) if parts else "no data available"))
    else:
        lines.append("CVSS: no data available")

    lines.append(f"EPSS: {_render_epss(briefing)}")
    lines.append(f"KEV: {_render_kev(briefing)}")

    if briefing.references:
        lines.append("References:")
        lines.extend(f"  - {ref.url}" for ref in briefing.references)

    lines.append("Sources:")
    for source, outcome in briefing.source_outcomes.items():
        lines.append(f"  - {_SOURCE_LABELS[source]}: {outcome.value}")

    return "\n".join(lines)


def _render_epss(briefing: VulnerabilityBriefing) -> str:
    if briefing.epss is not None:
        return f"{briefing.epss.score} (percentile {briefing.epss.percentile})"
    outcome = briefing.source_outcomes.get(SourceName.FIRST_EPSS)
    if outcome == SourceOutcome.NOT_FOUND:
        return "no data available"
    return "unavailable"


def _render_kev(briefing: VulnerabilityBriefing) -> str:
    if briefing.kev is not None:
        if briefing.kev.is_known_exploited:
            details = [
                p
                for p in (
                    f"added {briefing.kev.date_added}" if briefing.kev.date_added else None,
                    f"action: {briefing.kev.required_action}"
                    if briefing.kev.required_action
                    else None,
                    f"due {briefing.kev.due_date}" if briefing.kev.due_date else None,
                )
                if p
            ]
            suffix = f" ({', '.join(details)})" if details else ""
            return f"known exploited{suffix}"
        return "not in catalog"
    outcome = briefing.source_outcomes.get(SourceName.CISA_KEV)
    if outcome == SourceOutcome.NOT_FOUND:
        return "not in catalog"
    return "unavailable"
