"""FIRST EPSS source adapter.

Owns HTTP transport and FIRST's response schema; converts a successful
lookup into a `VulnerabilityBriefing` populated with EPSS-owned fields only.
Never renders output, touches storage, or imports CLI modules (see
docs/architecture.md, ADR 0001).
"""

from datetime import UTC, date, datetime

import httpx
from pydantic import ValidationError

from vulnbrief.adapters.exceptions import (
    SourceRateLimitError,
    SourceResponseError,
    SourceTimeoutError,
    SourceUnavailableError,
)
from vulnbrief.domain.enums import SourceName, SourceOutcome
from vulnbrief.domain.identifiers import normalize_cve_id
from vulnbrief.domain.models import EpssInfo, SourceProvenance, VulnerabilityBriefing

EPSS_BASE_URL = "https://api.first.org/data/v1/epss"
DEFAULT_TIMEOUT = 10.0


class EpssAdapter:
    """Retrieves one CVE's EPSS score/percentile and normalizes it into the
    domain model."""

    def __init__(
        self,
        transport: httpx.BaseTransport | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._client = httpx.Client(base_url=EPSS_BASE_URL, transport=transport, timeout=timeout)

    def get_cve(self, cve_id: str) -> VulnerabilityBriefing:
        """Fetch EPSS data for one CVE, raising a typed error on any
        expected failure (timeout, rate limit, unavailable, malformed). A
        successful response with no matching CVE is an explicit no-data
        result, not an error."""
        normalized_id = normalize_cve_id(cve_id)

        try:
            response = self._client.get("", params={"cve": normalized_id})
        except httpx.TimeoutException as exc:
            raise SourceTimeoutError(SourceName.FIRST_EPSS, "request timed out") from exc
        except httpx.TransportError as exc:
            raise SourceUnavailableError(SourceName.FIRST_EPSS, "transport error") from exc

        retrieved_at = datetime.now(UTC)
        self._raise_for_status(response)
        return self._parse_response(response, normalized_id, retrieved_at)

    def _raise_for_status(self, response: httpx.Response) -> None:
        if response.status_code in (403, 429):
            raise SourceRateLimitError(
                SourceName.FIRST_EPSS,
                f"rate limited (HTTP {response.status_code})",
                retry_after=response.headers.get("Retry-After"),
            )
        if response.status_code >= 500:
            raise SourceUnavailableError(
                SourceName.FIRST_EPSS, f"upstream unavailable (HTTP {response.status_code})"
            )
        if response.status_code != 200:
            raise SourceResponseError(
                SourceName.FIRST_EPSS, f"unexpected response status (HTTP {response.status_code})"
            )

    def _parse_response(
        self, response: httpx.Response, cve_id: str, retrieved_at: datetime
    ) -> VulnerabilityBriefing:
        try:
            data = response.json()
        except ValueError as exc:
            raise SourceResponseError(SourceName.FIRST_EPSS, "malformed JSON response") from exc

        return self._to_briefing(data, cve_id, retrieved_at)

    def _to_briefing(
        self, data: object, cve_id: str, retrieved_at: datetime
    ) -> VulnerabilityBriefing:
        if not isinstance(data, dict):
            raise SourceResponseError(SourceName.FIRST_EPSS, "unexpected response structure")

        entries = data.get("data")
        if not isinstance(entries, list):
            raise SourceResponseError(SourceName.FIRST_EPSS, "unexpected response structure")

        if not entries:
            epss = None
            outcome = SourceOutcome.NOT_FOUND
        else:
            entry = entries[0]
            if not isinstance(entry, dict):
                raise SourceResponseError(SourceName.FIRST_EPSS, "unexpected response structure")
            # The record must be for the CVE that was asked for; otherwise
            # another CVE's score would be reported under the requested ID.
            returned_id = entry.get("cve")
            if not isinstance(returned_id, str) or returned_id.strip().upper() != cve_id:
                raise SourceResponseError(
                    SourceName.FIRST_EPSS, "response does not match the requested CVE"
                )
            epss = _parse_epss_info(entry)
            outcome = SourceOutcome.FOUND

        return VulnerabilityBriefing(
            cve_id=cve_id,
            epss=epss,
            provenance=[
                SourceProvenance(
                    source=SourceName.FIRST_EPSS,
                    source_url=f"{EPSS_BASE_URL}?cve={cve_id}",
                    retrieved_at=retrieved_at,
                )
            ],
            source_outcomes={SourceName.FIRST_EPSS: outcome},
            retrieved_at=retrieved_at,
        )


def _parse_epss_info(entry: dict[str, object]) -> EpssInfo:
    try:
        score = float(entry["epss"])  # type: ignore[arg-type]
        percentile = float(entry["percentile"])  # type: ignore[arg-type]
    except (KeyError, TypeError, ValueError) as exc:
        raise SourceResponseError(
            SourceName.FIRST_EPSS, "invalid or missing EPSS score/percentile"
        ) from exc

    try:
        return EpssInfo(score=score, percentile=percentile, data_date=_parse_epss_date(entry))
    except ValidationError as exc:
        raise SourceResponseError(
            SourceName.FIRST_EPSS, "EPSS score/percentile out of range"
        ) from exc


def _parse_epss_date(entry: dict[str, object]) -> date | None:
    value = entry.get("date")
    if not isinstance(value, str) or not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None
