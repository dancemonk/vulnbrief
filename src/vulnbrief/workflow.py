"""The `show` command's application workflow: cache-first lookup, fresh
retrieval through the correlation service, and best-effort save.

No Typer, Rich, or HTTPX details here (see docs/architecture.md) -- this
module is exercised directly by tests using fake repositories/correlation
services, and by the CLI layer for real use. Warnings are surfaced through an
injected callback rather than printed, for the same reason.
"""

from collections.abc import Callable
from typing import Protocol

from vulnbrief.domain.enums import SourceOutcome
from vulnbrief.domain.identifiers import normalize_cve_id
from vulnbrief.domain.models import VulnerabilityBriefing
from vulnbrief.storage.repository import BriefingRepository, CacheError

# A cached briefing is only reusable when every attempted source reached a
# settled answer. FOUND and NOT_FOUND are real results; UNAVAILABLE and
# MALFORMED record a failed attempt, and reusing them would keep serving a
# transient outage forever (there is no TTL to age such a record out).
_USABLE_OUTCOMES = frozenset({SourceOutcome.FOUND, SourceOutcome.NOT_FOUND})


class BriefingCorrelator(Protocol):
    """Structural interface satisfied by CorrelationService."""

    def get_briefing(self, cve_id: str) -> VulnerabilityBriefing: ...


def _is_complete(briefing: VulnerabilityBriefing) -> bool:
    """True when no attempted source ended in a failure outcome."""
    return all(outcome in _USABLE_OUTCOMES for outcome in briefing.source_outcomes.values())


def run_show(
    cve_id: str,
    refresh: bool,
    repository: BriefingRepository,
    correlation_service: BriefingCorrelator,
    on_warning: Callable[[str], None] | None = None,
) -> VulnerabilityBriefing:
    """Validate the CVE ID, serve a complete cached briefing when available,
    otherwise retrieve fresh data and save it. Raises ValueError for an
    invalid CVE ID and whatever typed error the correlation service raises
    for an unrecoverable (NVD) failure. Cache problems never fail the lookup;
    they are reported through `on_warning` where the user should see them."""
    normalized_id = normalize_cve_id(cve_id)

    if not refresh:
        try:
            cached = repository.get(normalized_id)
        except CacheError:
            cached = None  # unreadable or invalid cache is treated as a miss
        if cached is not None and _is_complete(cached):
            return cached

    briefing = correlation_service.get_briefing(normalized_id)

    try:
        repository.put(briefing)
    except (CacheError, OSError) as exc:
        # A save failure must not fail an otherwise-successful lookup, but it
        # must not be silent either. OSError is included because a repository
        # implementation may surface a filesystem error the storage layer does
        # not own; nothing broader is caught, so genuine bugs still propagate.
        if on_warning is not None:
            on_warning(f"could not update cache: {exc}")

    return briefing
