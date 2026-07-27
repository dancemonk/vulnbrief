"""CISA Known Exploited Vulnerabilities (KEV) source adapter.

Owns HTTP transport and CISA's catalog schema; converts a successful lookup
into a `VulnerabilityBriefing` populated with KEV-owned fields only. Never
renders output, touches storage, or imports CLI modules (see
docs/architecture.md, ADR 0001).

CISA publishes the catalog as one bulk JSON file, not a per-CVE query API;
this adapter fetches the whole catalog and scans it for a matching `cveID`.
"""

import re
from datetime import UTC, date, datetime

import httpx

from vulnbrief.adapters.exceptions import (
    SourceRateLimitError,
    SourceResponseError,
    SourceTimeoutError,
    SourceUnavailableError,
)
from vulnbrief.domain.enums import SourceName, SourceOutcome
from vulnbrief.domain.identifiers import normalize_cve_id
from vulnbrief.domain.models import KevInfo, SourceProvenance, VulnerabilityBriefing

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_TIMEOUT = 10.0

_URL_PATTERN = re.compile(r"https?://\S+")


class KevAdapter:
    """Determines whether a CVE is in the CISA KEV catalog and normalizes the
    result into the domain model."""

    def __init__(
        self,
        transport: httpx.BaseTransport | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._client = httpx.Client(transport=transport, timeout=timeout)

    def get_cve(self, cve_id: str) -> VulnerabilityBriefing:
        """Fetch the KEV catalog and look up one CVE, raising a typed error
        on any expected failure (timeout, rate limit, unavailable,
        malformed). A successful fetch with no matching CVE is a valid
        negative result, not an error."""
        normalized_id = normalize_cve_id(cve_id)

        try:
            response = self._client.get(CISA_KEV_URL)
        except httpx.TimeoutException as exc:
            raise SourceTimeoutError(SourceName.CISA_KEV, "request timed out") from exc
        except httpx.TransportError as exc:
            raise SourceUnavailableError(SourceName.CISA_KEV, "transport error") from exc

        retrieved_at = datetime.now(UTC)
        self._raise_for_status(response)
        return self._parse_response(response, normalized_id, retrieved_at)

    def _raise_for_status(self, response: httpx.Response) -> None:
        if response.status_code in (403, 429):
            raise SourceRateLimitError(
                SourceName.CISA_KEV,
                f"rate limited (HTTP {response.status_code})",
                retry_after=response.headers.get("Retry-After"),
            )
        if response.status_code >= 500:
            raise SourceUnavailableError(
                SourceName.CISA_KEV, f"upstream unavailable (HTTP {response.status_code})"
            )
        if response.status_code != 200:
            raise SourceResponseError(
                SourceName.CISA_KEV, f"unexpected response status (HTTP {response.status_code})"
            )

    def _parse_response(
        self, response: httpx.Response, cve_id: str, retrieved_at: datetime
    ) -> VulnerabilityBriefing:
        try:
            data = response.json()
        except ValueError as exc:
            raise SourceResponseError(SourceName.CISA_KEV, "malformed JSON response") from exc

        try:
            return self._to_briefing(data, cve_id, retrieved_at)
        except (KeyError, TypeError, ValueError) as exc:
            raise SourceResponseError(SourceName.CISA_KEV, "unexpected response structure") from exc

    def _to_briefing(
        self, data: object, cve_id: str, retrieved_at: datetime
    ) -> VulnerabilityBriefing:
        if not isinstance(data, dict):
            raise SourceResponseError(SourceName.CISA_KEV, "unexpected response structure")

        vulnerabilities = data.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            raise SourceResponseError(SourceName.CISA_KEV, "unexpected response structure")

        entry = next(
            (
                v
                for v in vulnerabilities
                if isinstance(v, dict) and str(v.get("cveID", "")).upper() == cve_id
            ),
            None,
        )

        if entry is None:
            kev = KevInfo(is_known_exploited=False)
            outcome = SourceOutcome.NOT_FOUND
        else:
            kev = KevInfo(
                is_known_exploited=True,
                date_added=_parse_kev_date(entry.get("dateAdded")),
                required_action=_as_optional_str(entry.get("requiredAction")),
                due_date=_parse_kev_date(entry.get("dueDate")),
                ransomware_use=_as_optional_str(entry.get("knownRansomwareCampaignUse")),
                source_url=_extract_source_url(entry.get("notes")),
            )
            outcome = SourceOutcome.FOUND

        return VulnerabilityBriefing(
            cve_id=cve_id,
            kev=kev,
            provenance=[
                SourceProvenance(
                    source=SourceName.CISA_KEV,
                    source_url=CISA_KEV_URL,
                    retrieved_at=retrieved_at,
                )
            ],
            source_outcomes={SourceName.CISA_KEV: outcome},
            retrieved_at=retrieved_at,
        )


def _as_optional_str(value: object) -> str | None:
    return str(value) if isinstance(value, str) and value else None


def _parse_kev_date(value: object) -> date | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _extract_source_url(notes: object) -> str | None:
    if not isinstance(notes, str):
        return None
    match = _URL_PATTERN.search(notes)
    return match.group(0) if match else None
