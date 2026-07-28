"""Repository contract for caching normalized vulnerability briefings.

Storage code must not contain presentation logic and must remain isolated
behind this interface (see docs/architecture.md, V5).
"""

from typing import Protocol

from vulnbrief.domain.models import VulnerabilityBriefing


class CacheError(Exception):
    """Base for expected cache failures.

    Callers catch this to treat any cache problem as a miss. Backend details
    (sqlite3 errors, filesystem paths) are translated inside the storage
    implementation and must not reach application or CLI layers.
    """


class CacheUnavailableError(CacheError):
    """The cache backend could not be opened, initialized, read, or written."""


class CacheCorruptionError(CacheError):
    """A cached record exists but failed to validate against the domain
    model."""


class BriefingRepository(Protocol):
    """Structural interface for caching one briefing per CVE ID."""

    def get(self, cve_id: str) -> VulnerabilityBriefing | None:
        """Return the cached briefing for `cve_id`, or None on a cache
        miss. Raises CacheCorruptionError if a cached record exists but
        cannot be validated, or CacheUnavailableError if the backend itself
        cannot be read."""
        ...

    def put(self, briefing: VulnerabilityBriefing) -> None:
        """Store or replace the cached briefing for `briefing.cve_id`.

        Raises CacheUnavailableError if the write fails. An existing valid
        record must survive a failed replacement.
        """
        ...
