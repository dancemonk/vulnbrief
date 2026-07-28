"""A repository that caches nothing.

Used when the real cache backend cannot be opened: the lookup still runs
against live sources instead of being blocked by an unusable cache file. It
satisfies BriefingRepository, so no caller needs an optional repository.
"""

from vulnbrief.domain.models import VulnerabilityBriefing


class NullBriefingRepository:
    """Always a cache miss; stores nothing."""

    def get(self, cve_id: str) -> VulnerabilityBriefing | None:
        return None

    def put(self, briefing: VulnerabilityBriefing) -> None:
        return None
