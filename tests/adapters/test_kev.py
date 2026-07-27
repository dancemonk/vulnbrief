"""Tests for the CISA KEV source adapter. All HTTP is mocked via
httpx.MockTransport with sanitized fixtures -- no live network calls."""

import json
from collections.abc import Callable
from datetime import date
from pathlib import Path

import httpx
import pytest

from vulnbrief.adapters.exceptions import (
    SourceRateLimitError,
    SourceResponseError,
    SourceTimeoutError,
    SourceUnavailableError,
)
from vulnbrief.adapters.kev import KevAdapter
from vulnbrief.domain.enums import SourceName, SourceOutcome

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "kev"


def _load_fixture(name: str) -> dict[str, object]:
    data: dict[str, object] = json.loads((FIXTURES_DIR / name).read_text())
    return data


def _catalog_handler(fixture: str = "catalog.json") -> Callable[[httpx.Request], httpx.Response]:
    body = _load_fixture(fixture)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    return handler


def _adapter_for(handler: Callable[[httpx.Request], httpx.Response]) -> KevAdapter:
    return KevAdapter(transport=httpx.MockTransport(handler))


def test_matching_cve_returns_known_exploited_with_preserved_fields() -> None:
    adapter = _adapter_for(_catalog_handler())

    briefing = adapter.get_cve("CVE-2024-1111")

    assert briefing.kev is not None
    assert briefing.kev.is_known_exploited is True
    assert briefing.kev.date_added == date(2024, 5, 1)
    assert (
        briefing.kev.required_action == "Apply mitigations in accordance with vendor instructions."
    )
    assert briefing.kev.due_date == date(2024, 5, 22)
    assert briefing.kev.ransomware_use == "Known"
    assert briefing.kev.source_url == "https://example.com/advisories/CVE-2024-1111"
    assert briefing.source_outcomes[SourceName.CISA_KEV] == SourceOutcome.FOUND


def test_successful_catalog_response_with_no_match_is_negative_not_error() -> None:
    adapter = _adapter_for(_catalog_handler())

    briefing = adapter.get_cve("CVE-2099-9999")

    assert briefing.kev is not None
    assert briefing.kev.is_known_exploited is False
    assert briefing.source_outcomes[SourceName.CISA_KEV] == SourceOutcome.NOT_FOUND


def test_lowercase_cve_input_is_normalized_before_lookup() -> None:
    adapter = _adapter_for(_catalog_handler())

    briefing = adapter.get_cve("cve-2024-1111")

    assert briefing.cve_id == "CVE-2024-1111"
    assert briefing.kev is not None
    assert briefing.kev.is_known_exploited is True


def test_missing_optional_catalog_fields_are_none_not_fabricated() -> None:
    adapter = _adapter_for(_catalog_handler())

    briefing = adapter.get_cve("CVE-2024-2222")

    assert briefing.kev is not None
    assert briefing.kev.is_known_exploited is True
    assert briefing.kev.due_date is None
    assert briefing.kev.ransomware_use is None
    assert briefing.kev.source_url is None


def test_invalid_dates_and_field_types_do_not_crash_and_become_none() -> None:
    adapter = _adapter_for(_catalog_handler())

    briefing = adapter.get_cve("CVE-2024-3333")

    assert briefing.kev is not None
    assert briefing.kev.is_known_exploited is True
    assert briefing.kev.date_added is None
    assert briefing.kev.due_date is None
    assert briefing.kev.required_action is None
    assert briefing.kev.source_url is None


def test_timeout_raises_typed_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out", request=request)

    adapter = _adapter_for(handler)

    with pytest.raises(SourceTimeoutError):
        adapter.get_cve("CVE-2024-1111")


def test_transport_failure_raises_unavailable_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    adapter = _adapter_for(handler)

    with pytest.raises(SourceUnavailableError):
        adapter.get_cve("CVE-2024-1111")


def test_server_error_raises_unavailable_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "unavailable"})

    adapter = _adapter_for(handler)

    with pytest.raises(SourceUnavailableError):
        adapter.get_cve("CVE-2024-1111")


def test_rate_limit_response_raises_typed_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "60"}, json={})

    adapter = _adapter_for(handler)

    with pytest.raises(SourceRateLimitError) as exc_info:
        adapter.get_cve("CVE-2024-1111")
    assert exc_info.value.retry_after == "60"


def test_malformed_json_raises_typed_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not valid json{")

    adapter = _adapter_for(handler)

    with pytest.raises(SourceResponseError):
        adapter.get_cve("CVE-2024-1111")


def test_unexpected_catalog_structure_raises_typed_error() -> None:
    adapter = _adapter_for(_catalog_handler("malformed.json"))

    with pytest.raises(SourceResponseError):
        adapter.get_cve("CVE-2024-1111")


def test_provenance_and_retrieval_timestamp_recorded_on_match() -> None:
    adapter = _adapter_for(_catalog_handler())

    briefing = adapter.get_cve("CVE-2024-1111")

    assert len(briefing.provenance) == 1
    assert briefing.provenance[0].source == SourceName.CISA_KEV
    assert briefing.provenance[0].retrieved_at.tzinfo is not None
    assert briefing.retrieved_at.tzinfo is not None
    assert briefing.provenance[0].retrieved_at == briefing.retrieved_at


def test_provenance_and_retrieval_timestamp_recorded_on_no_match() -> None:
    adapter = _adapter_for(_catalog_handler())

    briefing = adapter.get_cve("CVE-2099-9999")

    assert len(briefing.provenance) == 1
    assert briefing.provenance[0].source == SourceName.CISA_KEV
    assert briefing.retrieved_at.tzinfo is not None


def test_source_failure_is_never_represented_as_negative_kev_result() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    adapter = _adapter_for(handler)

    with pytest.raises(SourceUnavailableError):
        adapter.get_cve("CVE-2024-1111")
    # A failure must raise, never fall through to a fabricated
    # KevInfo(is_known_exploited=False) result.


def test_no_live_network_calls_are_ever_made() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json=_load_fixture("catalog.json"))

    adapter = _adapter_for(handler)
    adapter.get_cve("CVE-2024-1111")

    assert calls == [
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    ]


def test_explicit_timeout_is_configured_not_implicit() -> None:
    adapter = _adapter_for(_catalog_handler())

    assert adapter._client.timeout.connect == 10.0
