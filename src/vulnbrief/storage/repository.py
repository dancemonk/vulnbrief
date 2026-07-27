"""Repository contract for caching normalized vulnerability briefings.

Storage code must not contain presentation logic and must remain isolated
behind this interface (see docs/architecture.md, V5).
"""

from typing import Protocol

from vulnbrief.domain.models import VulnerabilityBriefing


class CacheCorruptionError(Exception):
    """A cached record exists but failed to validate against the domain
    model."""


class BriefingRepository(Protocol):
    """Structural interface for caching one briefing per CVE ID."""

    def get(self, cve_id: str) -> VulnerabilityBriefing | None:
        """Return the cached briefing for `cve_id`, or None on a cache
        miss. Raises CacheCorruptionError if a cached record exists but
        cannot be validated."""
        ...

    def put(self, briefing: VulnerabilityBriefing) -> None:
        """Store or replace the cached briefing for `briefing.cve_id`."""
        ...
