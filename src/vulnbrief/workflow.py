"""The `show` command's application workflow: cache-first lookup, fresh
retrieval through the correlation service, and best-effort save.

No Typer, Rich, or HTTPX details here (see docs/architecture.md) -- this
module is exercised directly by tests using fake repositories/correlation
services, and by the CLI layer for real use.
"""

from typing import Protocol

from vulnbrief.domain.identifiers import normalize_cve_id
from vulnbrief.domain.models import VulnerabilityBriefing
from vulnbrief.storage.repository import BriefingRepository, CacheCorruptionError


class BriefingCorrelator(Protocol):
    """Structural interface satisfied by CorrelationService."""

    def get_briefing(self, cve_id: str) -> VulnerabilityBriefing: ...


def run_show(
    cve_id: str,
    refresh: bool,
    repository: BriefingRepository,
    correlation_service: BriefingCorrelator,
) -> VulnerabilityBriefing:
    """Validate the CVE ID, serve a valid cached briefing when available,
    otherwise retrieve fresh data and save it. Raises ValueError for an
    invalid CVE ID and whatever typed error the correlation service raises
    for an unrecoverable (NVD) failure."""
    normalized_id = normalize_cve_id(cve_id)

    if not refresh:
        try:
            cached = repository.get(normalized_id)
        except CacheCorruptionError:
            cached = None
        if cached is not None:
            return cached

    briefing = correlation_service.get_briefing(normalized_id)

    try:
        repository.put(briefing)
    except Exception:
        pass  # a save failure must not fail an otherwise-successful lookup

    return briefing
