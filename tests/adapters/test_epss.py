"""Tests for the FIRST EPSS source adapter. All HTTP is mocked via
httpx.MockTransport with sanitized fixtures -- no live network calls."""

import json
from collections.abc import Callable
from datetime import date
from pathlib import Path

import httpx
import pytest

from vulnbrief.adapters.epss import EpssAdapter
from vulnbrief.adapters.exceptions import (
    SourceRateLimitError,
    SourceResponseError,
    SourceTimeoutError,
    SourceUnavailableError,
)
from vulnbrief.domain.enums import SourceName, SourceOutcome

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "epss"


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


def _adapter_for(handler: Callable[[httpx.Request], httpx.Response]) -> EpssAdapter:
    return EpssAdapter(transport=httpx.MockTransport(handler))


def test_successful_response_maps_to_epss_info() -> None:
    adapter = _adapter_for(_json_handler("success.json"))

    briefing = adapter.get_cve("CVE-2024-1234")

    assert briefing.epss is not None
    assert briefing.epss.score == 0.42
    assert briefing.epss.percentile == 0.9
    assert briefing.epss.data_date == date(2026, 1, 1)
    assert briefing.source_outcomes[SourceName.FIRST_EPSS] == SourceOutcome.FOUND


def test_successful_response_with_no_match_is_explicit_no_data() -> None:
    adapter = _adapter_for(_json_handler("not_found.json"))

    briefing = adapter.get_cve("CVE-2024-0000")

    assert briefing.epss is None
    assert briefing.source_outcomes[SourceName.FIRST_EPSS] == SourceOutcome.NOT_FOUND


def _body_handler(body: object) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    return handler


def test_response_for_a_different_cve_is_rejected() -> None:
    # success.json describes CVE-2024-1234. Requesting a different CVE must
    # not return that score relabelled with the requested ID.
    adapter = _adapter_for(_json_handler("success.json"))

    with pytest.raises(SourceResponseError):
        adapter.get_cve("CVE-2024-9998")


@pytest.mark.parametrize("returned_id", [None, 42, ["CVE-2024-1234"], {"cve": "CVE-2024-1234"}])
def test_non_string_cve_identifier_raises_typed_error(returned_id: object) -> None:
    adapter = _adapter_for(
        _body_handler({"data": [{"cve": returned_id, "epss": "0.1", "percentile": "0.2"}]})
    )

    with pytest.raises(SourceResponseError):
        adapter.get_cve("CVE-2024-1234")


def test_missing_cve_identifier_raises_typed_error() -> None:
    adapter = _adapter_for(_body_handler({"data": [{"epss": "0.1", "percentile": "0.2"}]}))

    with pytest.raises(SourceResponseError):
        adapter.get_cve("CVE-2024-1234")


def test_returned_cve_identifier_is_matched_case_insensitively() -> None:
    adapter = _adapter_for(
        _body_handler({"data": [{"cve": "cve-2024-1234", "epss": "0.1", "percentile": "0.2"}]})
    )

    briefing = adapter.get_cve("CVE-2024-1234")

    assert briefing.epss is not None
    assert briefing.epss.score == 0.1


def test_empty_data_remains_no_match_not_a_mismatch_failure() -> None:
    # The no-match path must stay distinguishable from a rejected record.
    adapter = _adapter_for(_body_handler({"data": []}))

    briefing = adapter.get_cve("CVE-2024-0000")

    assert briefing.epss is None
    assert briefing.source_outcomes[SourceName.FIRST_EPSS] == SourceOutcome.NOT_FOUND


def test_zero_score_and_percentile_are_preserved_not_missing() -> None:
    adapter = _adapter_for(_json_handler("zero_score.json"))

    briefing = adapter.get_cve("CVE-2024-5555")

    assert briefing.epss is not None
    assert briefing.epss.score == 0.0
    assert briefing.epss.percentile == 0.0
    assert briefing.source_outcomes[SourceName.FIRST_EPSS] == SourceOutcome.FOUND


def test_lowercase_cve_input_is_normalized_before_request() -> None:
    captured_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, json=_load_fixture("success.json"))

    adapter = _adapter_for(handler)
    briefing = adapter.get_cve("cve-2024-1234")

    assert briefing.cve_id == "CVE-2024-1234"
    assert captured_requests[0].url.params["cve"] == "CVE-2024-1234"


def test_timeout_raises_typed_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out", request=request)

    adapter = _adapter_for(handler)

    with pytest.raises(SourceTimeoutError):
        adapter.get_cve("CVE-2024-1234")


def test_rate_limit_response_raises_typed_error_with_retry_after() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "45"}, json={})

    adapter = _adapter_for(handler)

    with pytest.raises(SourceRateLimitError) as exc_info:
        adapter.get_cve("CVE-2024-1234")
    assert exc_info.value.retry_after == "45"


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


def test_invalid_non_numeric_score_raises_typed_error() -> None:
    adapter = _adapter_for(_json_handler("invalid_score.json"))

    with pytest.raises(SourceResponseError):
        adapter.get_cve("CVE-2024-6666")


def test_score_above_one_raises_typed_error() -> None:
    adapter = _adapter_for(_json_handler("out_of_range.json"))

    with pytest.raises(SourceResponseError):
        adapter.get_cve("CVE-2024-7777")


def test_percentile_below_zero_raises_typed_error() -> None:
    adapter = _adapter_for(_json_handler("percentile_out_of_range.json"))

    with pytest.raises(SourceResponseError):
        adapter.get_cve("CVE-2024-9999")


def test_invalid_date_becomes_none_not_fatal() -> None:
    adapter = _adapter_for(_json_handler("invalid_date.json"))

    briefing = adapter.get_cve("CVE-2024-8888")

    assert briefing.epss is not None
    assert briefing.epss.data_date is None


def test_provenance_and_retrieval_timestamp_recorded_on_match() -> None:
    adapter = _adapter_for(_json_handler("success.json"))

    briefing = adapter.get_cve("CVE-2024-1234")

    assert len(briefing.provenance) == 1
    assert briefing.provenance[0].source == SourceName.FIRST_EPSS
    assert briefing.provenance[0].retrieved_at.tzinfo is not None
    assert briefing.retrieved_at.tzinfo is not None
    assert briefing.provenance[0].retrieved_at == briefing.retrieved_at


def test_provenance_and_retrieval_timestamp_recorded_on_no_match() -> None:
    adapter = _adapter_for(_json_handler("not_found.json"))

    briefing = adapter.get_cve("CVE-2024-0000")

    assert len(briefing.provenance) == 1
    assert briefing.provenance[0].source == SourceName.FIRST_EPSS
    assert briefing.retrieved_at.tzinfo is not None


def test_no_data_and_source_failure_remain_distinct() -> None:
    no_data_adapter = _adapter_for(_json_handler("not_found.json"))
    no_data_briefing = no_data_adapter.get_cve("CVE-2024-0000")
    assert no_data_briefing.epss is None
    assert no_data_briefing.source_outcomes[SourceName.FIRST_EPSS] == SourceOutcome.NOT_FOUND

    def failing_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    failure_adapter = _adapter_for(failing_handler)
    with pytest.raises(SourceUnavailableError):
        failure_adapter.get_cve("CVE-2024-0000")
    # A source failure must raise, never fall through to the same
    # epss=None/NOT_FOUND shape a genuine no-data result produces.


def test_no_live_network_calls_are_ever_made() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json=_load_fixture("success.json"))

    adapter = _adapter_for(handler)
    adapter.get_cve("CVE-2024-1234")

    assert calls == ["https://api.first.org/data/v1/epss/?cve=CVE-2024-1234"]


def test_explicit_timeout_is_configured_not_implicit() -> None:
    adapter = _adapter_for(_json_handler("success.json"))

    assert adapter._client.timeout.connect == 10.0
