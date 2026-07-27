"""Rich rendering of a normalized vulnerability briefing.

Accesses no adapter, HTTP client, or storage implementation (V4). Content is
deliberately unstyled beyond structural bold labels, so output stays
understandable without color (see docs/architecture.md, Issue #10 AC).
"""

import io

from rich.box import ROUNDED
from rich.console import Console, ConsoleRenderable, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vulnbrief.domain.enums import SourceName, SourceOutcome
from vulnbrief.domain.models import VulnerabilityBriefing

_SOURCE_LABELS = {
    SourceName.NVD: "NVD",
    SourceName.CISA_KEV: "CISA KEV",
    SourceName.FIRST_EPSS: "FIRST EPSS",
}


def build_renderable(briefing: VulnerabilityBriefing) -> Panel:
    """Pure construction of the Rich renderable tree for one briefing. No
    I/O, no console -- just data in, Rich objects out."""
    sections: list[ConsoleRenderable] = []

    if briefing.description:
        sections.append(Text(briefing.description))

    published = briefing.published_at.isoformat() if briefing.published_at else "unknown"
    modified = briefing.modified_at.isoformat() if briefing.modified_at else "unknown"
    sections.append(Text(f"Published: {published}   Modified: {modified}"))

    sections.append(_build_facts_table(briefing))

    if briefing.references:
        ref_lines = "\n".join(f"- {ref.url}" for ref in briefing.references)
        sections.append(Text(f"References:\n{ref_lines}"))

    sections.append(_build_sources_table(briefing))

    return Panel(Group(*sections), title=briefing.cve_id, box=ROUNDED)


def _build_facts_table(briefing: VulnerabilityBriefing) -> Table:
    table = Table(show_header=False, box=None, padding=(0, 1, 0, 0))
    table.add_column("label", style="bold")
    table.add_column("value")

    table.add_row("CVSS", _render_cvss(briefing))
    table.add_row("EPSS", _render_epss(briefing))
    table.add_row("KEV", _render_kev(briefing))

    return table


def _render_cvss(briefing: VulnerabilityBriefing) -> str:
    if briefing.cvss is None:
        return "no data available"
    parts = [
        p
        for p in (
            str(briefing.cvss.score) if briefing.cvss.score is not None else None,
            briefing.cvss.severity,
            briefing.cvss.vector,
        )
        if p
    ]
    return ", ".join(parts) if parts else "no data available"


def _render_epss(briefing: VulnerabilityBriefing) -> str:
    if briefing.epss is not None:
        return f"{briefing.epss.score} ({briefing.epss.percentile} percentile)"
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
            return f"Known Exploited{suffix}"
        return "Not in KEV catalog"
    outcome = briefing.source_outcomes.get(SourceName.CISA_KEV)
    if outcome == SourceOutcome.NOT_FOUND:
        return "Not in KEV catalog"
    return "KEV status unavailable"


def _build_sources_table(briefing: VulnerabilityBriefing) -> Table:
    provenance_by_source = {p.source: p for p in briefing.provenance}

    table = Table(title="Sources", show_header=True, box=None)
    table.add_column("Source")
    table.add_column("Outcome")
    table.add_column("Retrieved At")

    for source, outcome in briefing.source_outcomes.items():
        provenance = provenance_by_source.get(source)
        retrieved_at = provenance.retrieved_at.isoformat() if provenance else "—"
        table.add_row(_SOURCE_LABELS[source], outcome.value.replace("_", " ").title(), retrieved_at)

    return table


def render_briefing_text(
    briefing: VulnerabilityBriefing, *, width: int = 100, no_color: bool = True
) -> str:
    """Render to a plain string via an in-memory Console. Used by tests for
    deterministic, width/color-controlled output."""
    buffer = io.StringIO()
    console = Console(file=buffer, width=width, no_color=no_color, force_terminal=not no_color)
    console.print(build_renderable(briefing))
    return buffer.getvalue()
