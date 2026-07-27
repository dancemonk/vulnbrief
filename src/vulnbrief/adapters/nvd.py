"""NVD CVE source adapter.

Owns HTTP transport and NVD's response schema; converts a successful lookup
into a `VulnerabilityBriefing` populated with NVD-owned fields only. Never
renders output, touches storage, or imports CLI modules (see
docs/architecture.md, ADR 0001).
"""

import os
from datetime import UTC, datetime

import httpx

from vulnbrief.adapters.exceptions import (
    SourceNotFoundError,
    SourceRateLimitError,
    SourceResponseError,
    SourceTimeoutError,
    SourceUnavailableError,
)
from vulnbrief.domain.enums import SourceName, SourceOutcome
from vulnbrief.domain.identifiers import normalize_cve_id
from vulnbrief.domain.models import CvssInfo, Reference, SourceProvenance, VulnerabilityBriefing

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_TIMEOUT = 10.0

_CVSS_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


class NvdAdapter:
    """Retrieves one CVE from NVD and normalizes it into the domain model."""

    def __init__(
        self,
        transport: httpx.BaseTransport | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        api_key: str | None = None,
    ) -> None:
        self._api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY")
        self._client = httpx.Client(
            base_url=NVD_BASE_URL,
            transport=transport,
            timeout=timeout,
        )

    def get_cve(self, cve_id: str) -> VulnerabilityBriefing:
        """Fetch one CVE from NVD, raising a typed error on any expected
        failure (not found, timeout, rate limit, unavailable, malformed)."""
        normalized_id = normalize_cve_id(cve_id)
        headers = {"apiKey": self._api_key} if self._api_key else None

        try:
            response = self._client.get("", params={"cveId": normalized_id}, headers=headers)
        except httpx.TimeoutException as exc:
            raise SourceTimeoutError(SourceName.NVD, "request timed out") from exc
        except httpx.TransportError as exc:
            raise SourceUnavailableError(SourceName.NVD, "transport error") from exc

        retrieved_at = datetime.now(UTC)
        self._raise_for_status(response)
        return self._parse_response(response, normalized_id, retrieved_at)

    def _raise_for_status(self, response: httpx.Response) -> None:
        if response.status_code in (403, 429):
            raise SourceRateLimitError(
                SourceName.NVD,
                f"rate limited (HTTP {response.status_code})",
                retry_after=response.headers.get("Retry-After"),
            )
        if response.status_code >= 500:
            raise SourceUnavailableError(
                SourceName.NVD, f"upstream unavailable (HTTP {response.status_code})"
            )
        if response.status_code != 200:
            raise SourceResponseError(
                SourceName.NVD, f"unexpected response status (HTTP {response.status_code})"
            )

    def _parse_response(
        self, response: httpx.Response, cve_id: str, retrieved_at: datetime
    ) -> VulnerabilityBriefing:
        try:
            data = response.json()
        except ValueError as exc:
            raise SourceResponseError(SourceName.NVD, "malformed JSON response") from exc

        try:
            return self._to_briefing(data, cve_id, retrieved_at)
        except SourceNotFoundError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise SourceResponseError(SourceName.NVD, "unexpected response structure") from exc

    def _to_briefing(
        self, data: object, cve_id: str, retrieved_at: datetime
    ) -> VulnerabilityBriefing:
        if not isinstance(data, dict):
            raise SourceResponseError(SourceName.NVD, "unexpected response structure")

        vulnerabilities = data.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            raise SourceResponseError(SourceName.NVD, "unexpected response structure")
        if not vulnerabilities:
            raise SourceNotFoundError(SourceName.NVD, f"{cve_id} not found in NVD")

        cve = vulnerabilities[0].get("cve")
        if not isinstance(cve, dict) or "id" not in cve:
            raise SourceResponseError(SourceName.NVD, "unexpected response structure")

        return VulnerabilityBriefing(
            cve_id=cve_id,
            description=_extract_description(cve),
            published_at=_parse_nvd_datetime(cve.get("published")),
            modified_at=_parse_nvd_datetime(cve.get("lastModified")),
            cvss=_extract_cvss(cve.get("metrics")),
            references=_extract_references(cve.get("references")),
            provenance=[
                SourceProvenance(
                    source=SourceName.NVD,
                    source_url=f"{NVD_BASE_URL}?cveId={cve_id}",
                    retrieved_at=retrieved_at,
                )
            ],
            source_outcomes={SourceName.NVD: SourceOutcome.FOUND},
            retrieved_at=retrieved_at,
        )


def _extract_description(cve: dict[str, object]) -> str | None:
    descriptions = cve.get("descriptions")
    if not isinstance(descriptions, list):
        return None
    english = next(
        (d.get("value") for d in descriptions if isinstance(d, dict) and d.get("lang") == "en"),
        None,
    )
    if english is not None:
        return str(english)
    if descriptions and isinstance(descriptions[0], dict):
        value = descriptions[0].get("value")
        return str(value) if value is not None else None
    return None


def _parse_nvd_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _extract_cvss(metrics: object) -> CvssInfo | None:
    if not isinstance(metrics, dict):
        return None
    for key in _CVSS_METRIC_KEYS:
        entries = metrics.get(key)
        if isinstance(entries, list) and entries:
            entry = entries[0]
            if not isinstance(entry, dict):
                continue
            cvss_data = entry.get("cvssData")
            if not isinstance(cvss_data, dict):
                continue
            return CvssInfo(
                score=cvss_data.get("baseScore"),
                severity=cvss_data.get("baseSeverity", entry.get("baseSeverity")),
                vector=cvss_data.get("vectorString"),
                version=cvss_data.get("version"),
            )
    return None


def _extract_references(references: object) -> list[Reference]:
    if not isinstance(references, list):
        return []
    result: list[Reference] = []
    for ref in references:
        if isinstance(ref, dict) and ref.get("url"):
            result.append(Reference(url=str(ref["url"]), source=ref.get("source")))
    return result
