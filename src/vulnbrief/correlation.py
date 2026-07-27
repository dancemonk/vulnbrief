"""Correlation service: combines NVD, CISA KEV, and FIRST EPSS results into
one normalized vulnerability briefing.

Depends only on the `SourceAdapter` structural interface, never on concrete
HTTP details (see docs/architecture.md). NVD is required (V6): its failure
propagates as a typed error and prevents a complete result. CISA KEV and
FIRST EPSS are optional; their failure preserves valid NVD data instead of
discarding it.
"""

from datetime import UTC, datetime
from typing import Protocol

from vulnbrief.adapters.exceptions import SourceError, SourceResponseError
from vulnbrief.domain.enums import SourceName, SourceOutcome
from vulnbrief.domain.identifiers import normalize_cve_id
from vulnbrief.domain.models import VulnerabilityBriefing


class SourceAdapter(Protocol):
    """Structural interface satisfied by NvdAdapter, KevAdapter, and
    EpssAdapter without any inheritance relationship."""

    def get_cve(self, cve_id: str) -> VulnerabilityBriefing: ...


class CorrelationService:
    """Calls each source adapter for one CVE and merges the results."""

    def __init__(self, nvd: SourceAdapter, kev: SourceAdapter, epss: SourceAdapter) -> None:
        self._nvd = nvd
        self._kev = kev
        self._epss = epss

    def get_briefing(self, cve_id: str) -> VulnerabilityBriefing:
        """Retrieve and merge one CVE's briefing. Raises whatever typed
        error NVD raises on failure; KEV/EPSS failures are recorded as
        partial-source outcomes instead."""
        normalized_id = normalize_cve_id(cve_id)
        nvd_result = self._nvd.get_cve(normalized_id)

        kev_result, kev_outcome = self._call_optional(self._kev, SourceName.CISA_KEV, normalized_id)
        epss_result, epss_outcome = self._call_optional(
            self._epss, SourceName.FIRST_EPSS, normalized_id
        )

        provenance = list(nvd_result.provenance)
        if kev_result is not None:
            provenance += kev_result.provenance
        if epss_result is not None:
            provenance += epss_result.provenance

        source_outcomes = dict(nvd_result.source_outcomes)
        source_outcomes[SourceName.CISA_KEV] = kev_outcome
        source_outcomes[SourceName.FIRST_EPSS] = epss_outcome

        return VulnerabilityBriefing(
            cve_id=nvd_result.cve_id,
            description=nvd_result.description,
            published_at=nvd_result.published_at,
            modified_at=nvd_result.modified_at,
            cvss=nvd_result.cvss,
            epss=epss_result.epss if epss_result is not None else None,
            kev=kev_result.kev if kev_result is not None else None,
            references=nvd_result.references,
            provenance=provenance,
            source_outcomes=source_outcomes,
            retrieved_at=datetime.now(UTC),
        )

    def _call_optional(
        self, adapter: SourceAdapter, source: SourceName, cve_id: str
    ) -> tuple[VulnerabilityBriefing | None, SourceOutcome]:
        try:
            result = adapter.get_cve(cve_id)
        except SourceResponseError:
            return None, SourceOutcome.MALFORMED
        except SourceError:
            return None, SourceOutcome.UNAVAILABLE
        return result, result.source_outcomes[source]
