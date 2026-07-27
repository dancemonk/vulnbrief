"""Tests for the NVD source adapter. All HTTP is mocked via
httpx.MockTransport with sanitized fixtures -- no live network calls."""

import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from vulnbrief.adapters.exceptions import (
    SourceNotFoundError,
    SourceRateLimitError,
    SourceResponseError,
    SourceTimeoutError,
    SourceUnavailableError,
)
from vulnbrief.adapters.nvd import NvdAdapter
from vulnbrief.domain.enums import SourceName, SourceOutcome

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "nvd"


def _load_fixture(name: str) -> dict[str, object]:
    data: dict[str, object] = json.loads((FIXTURES_DIR / name).read_text())
    return data


def _json_handler(
    fixture: str, status_code: int = 200
) -> Callable[[httpx.Request], httpx.Response]:
    body = _load_fixture(fixture)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=body)

    return handler


def _adapter_for(
    handler: Callable[[httpx.Request], httpx.Response], api_key: str | None = None
) -> NvdAdapter:
    return NvdAdapter(transport=httpx.MockTransport(handler), api_key=api_key)


def test_successful_response_maps_to_briefing() -> None:
    adapter = _adapter_for(_json_handler("success_full.json"))

    briefing = adapter.get_cve("CVE-2024-1234")

    assert briefing.cve_id == "CVE-2024-1234"
    assert briefing.description == "Example vulnerability in Example Product."
    assert briefing.published_at is not None
    assert briefing.modified_at is not None
    assert len(briefing.references) == 2
    assert briefing.source_outcomes[SourceName.NVD] == SourceOutcome.FOUND


def test_lowercase_cve_input_is_normalized_before_request() -> None:
    captured_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, json=_load_fixture("success_full.json"))

    adapter = _adapter_for(handler)
    briefing = adapter.get_cve("cve-2024-1234")

    assert briefing.cve_id == "CVE-2024-1234"
    assert captured_requests[0].url.params["cveId"] == "CVE-2024-1234"


def test_not_found_raises_typed_error() -> None:
    adapter = _adapter_for(_json_handler("not_found.json"))

    with pytest.raises(SourceNotFoundError):
        adapter.get_cve("CVE-2024-9999")


def test_missing_cvss_data_is_none_not_fabricated() -> None:
    adapter = _adapter_for(_json_handler("success_partial.json"))

    briefing = adapter.get_cve("CVE-2024-5678")

    assert briefing.cvss is None


def test_multiple_cvss_versions_prefers_highest_available() -> None:
    adapter = _adapter_for(_json_handler("success_full.json"))

    briefing = adapter.get_cve("CVE-2024-1234")

    assert briefing.cvss is not None
    assert briefing.cvss.version == "3.1"
    assert briefing.cvss.score == 9.8


def test_missing_optional_fields_default_appropriately() -> None:
    adapter = _adapter_for(_json_handler("success_partial.json"))

    briefing = adapter.get_cve("CVE-2024-5678")

    assert briefing.description is None
    assert briefing.references == []
    assert briefing.cvss is None


def test_timeout_raises_typed_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out", request=request)

    adapter = _adapter_for(handler)

    with pytest.raises(SourceTimeoutError):
        adapter.get_cve("CVE-2024-1234")


def test_rate_limit_response_raises_typed_error_with_retry_after() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "30"}, json={})

    adapter = _adapter_for(handler)

    with pytest.raises(SourceRateLimitError) as exc_info:
        adapter.get_cve("CVE-2024-1234")
    assert exc_info.value.retry_after == "30"


def test_transport_failure_raises_unavailable_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    adapter = _adapter_for(handler)

    with pytest.raises(SourceUnavailableError):
        adapter.get_cve("CVE-2024-1234")


def test_server_error_raises_unavailable_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "unavailable"})

    adapter = _adapter_for(handler)

    with pytest.raises(SourceUnavailableError):
        adapter.get_cve("CVE-2024-1234")


def test_malformed_json_raises_typed_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not valid json{")

    adapter = _adapter_for(handler)

    with pytest.raises(SourceResponseError):
        adapter.get_cve("CVE-2024-1234")


def test_unexpected_response_structure_raises_typed_error() -> None:
    adapter = _adapter_for(_json_handler("malformed.json"))

    with pytest.raises(SourceResponseError):
        adapter.get_cve("CVE-2024-1234")


def test_provenance_and_retrieval_timestamp_are_recorded() -> None:
    adapter = _adapter_for(_json_handler("success_full.json"))

    briefing = adapter.get_cve("CVE-2024-1234")

    assert len(briefing.provenance) == 1
    assert briefing.provenance[0].source == SourceName.NVD
    assert briefing.provenance[0].retrieved_at.tzinfo is not None
    assert briefing.retrieved_at.tzinfo is not None
    assert briefing.provenance[0].retrieved_at == briefing.retrieved_at


def test_explicit_timeout_is_configured_not_implicit() -> None:
    adapter = _adapter_for(_json_handler("success_full.json"))

    assert adapter._client.timeout.connect == 10.0


def test_api_key_is_never_exposed_in_error_text() -> None:
    secret = "super-secret-nvd-key"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "unavailable"})

    adapter = _adapter_for(handler, api_key=secret)

    with pytest.raises(SourceUnavailableError) as exc_info:
        adapter.get_cve("CVE-2024-1234")

    assert secret not in str(exc_info.value)


def test_api_key_is_never_exposed_in_rate_limit_error_text() -> None:
    secret = "super-secret-nvd-key"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={})

    adapter = _adapter_for(handler, api_key=secret)

    with pytest.raises(SourceRateLimitError) as exc_info:
        adapter.get_cve("CVE-2024-1234")

    assert secret not in str(exc_info.value)
