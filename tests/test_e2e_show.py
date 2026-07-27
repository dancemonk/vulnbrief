"""End-to-end tests for `vulnbrief show`.

Unlike tests/test_cli.py (which substitutes fake repository/correlation
objects to unit-test CLI wiring in isolation), these tests wire the real
NvdAdapter/KevAdapter/EpssAdapter and a real CorrelationService and
SqliteBriefingRepository together, invoked through the real CliRunner/typer
app. Only two things are substituted: the HTTP transport (mocked, via saved
fixtures already used by tests/adapters/) and the database location
(temporary, via VULNBRIEF_DB_PATH) -- so these tests genuinely exercise
adapter parsing, correlation merging, cache persistence, and Rich rendering
together, with no live network access and no API keys required.
"""

import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

import vulnbrief.cli as cli
from vulnbrief.adapters import EpssAdapter, KevAdapter, NvdAdapter
from vulnbrief.correlation import CorrelationService

runner = CliRunner()

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_fixture(source: str, name: str) -> dict[str, object]:
    data: dict[str, object] = json.loads((FIXTURES_DIR / source / name).read_text())
    return data


Handler = Callable[[httpx.Request], httpx.Response]


def _json_handler(body: dict[str, object], status_code: int = 200) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=body)

    return handler


def _build_correlation_service(
    nvd_handler: Handler, kev_handler: Handler, epss_handler: Handler
) -> CorrelationService:
    return CorrelationService(
        nvd=NvdAdapter(transport=httpx.MockTransport(nvd_handler)),
        kev=KevAdapter(transport=httpx.MockTransport(kev_handler)),
        epss=EpssAdapter(transport=httpx.MockTransport(epss_handler)),
    )


def _use_temp_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("VULNBRIEF_DB_PATH", str(tmp_path / "cache.db"))


def test_e2e_valid_cve_with_nvd_kev_and_epss_data(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_temp_cache(monkeypatch, tmp_path)
    service = _build_correlation_service(
        nvd_handler=_json_handler(_load_fixture("nvd", "success_full.json")),
        kev_handler=_json_handler(_load_fixture("kev", "catalog.json")),
        epss_handler=_json_handler(_load_fixture("epss", "success.json")),
    )
    monkeypatch.setattr(cli, "build_correlation_service", lambda: service)

    result = runner.invoke(cli.app, ["show", "CVE-2024-1111"])

    assert result.exit_code == 0
    assert "CVE-2024-1111" in result.output
    assert "NVD" in result.output
    assert "CISA KEV" in result.output
    assert "FIRST EPSS" in result.output
    assert "Known Exploited" in result.output
    assert "0.42" in result.output


def test_e2e_valid_cve_with_no_kev_entry(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_temp_cache(monkeypatch, tmp_path)
    service = _build_correlation_service(
        nvd_handler=_json_handler(_load_fixture("nvd", "success_full.json")),
        kev_handler=_json_handler(_load_fixture("kev", "catalog.json")),
        epss_handler=_json_handler(_load_fixture("epss", "success.json")),
    )
    monkeypatch.setattr(cli, "build_correlation_service", lambda: service)

    result = runner.invoke(cli.app, ["show", "CVE-2099-0000"])

    assert result.exit_code == 0
    assert "Not in KEV catalog" in result.output
    assert "0.42" in result.output  # EPSS data still present


def test_e2e_valid_cve_with_missing_epss_data(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_temp_cache(monkeypatch, tmp_path)
    service = _build_correlation_service(
        nvd_handler=_json_handler(_load_fixture("nvd", "success_full.json")),
        kev_handler=_json_handler(_load_fixture("kev", "catalog.json")),
        epss_handler=_json_handler(_load_fixture("epss", "not_found.json")),
    )
    monkeypatch.setattr(cli, "build_correlation_service", lambda: service)

    result = runner.invoke(cli.app, ["show", "CVE-2024-1111"])

    assert result.exit_code == 0
    assert "Known Exploited" in result.output  # KEV data still present
    assert "no data available" in result.output  # EPSS not found


def test_e2e_invalid_cve_identifier_never_calls_any_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_temp_cache(monkeypatch, tmp_path)
    calls: list[str] = []

    def tracking_handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={})

    service = _build_correlation_service(tracking_handler, tracking_handler, tracking_handler)
    monkeypatch.setattr(cli, "build_correlation_service", lambda: service)

    result = runner.invoke(cli.app, ["show", "not-a-cve"])

    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert calls == []


def test_e2e_external_source_timeout_exits_nonzero_without_traceback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_temp_cache(monkeypatch, tmp_path)
    kev_calls: list[str] = []
    epss_calls: list[str] = []

    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out", request=request)

    def kev_handler(request: httpx.Request) -> httpx.Response:
        kev_calls.append(str(request.url))
        return httpx.Response(200, json=_load_fixture("kev", "catalog.json"))

    def epss_handler(request: httpx.Request) -> httpx.Response:
        epss_calls.append(str(request.url))
        return httpx.Response(200, json=_load_fixture("epss", "success.json"))

    service = _build_correlation_service(timeout_handler, kev_handler, epss_handler)
    monkeypatch.setattr(cli, "build_correlation_service", lambda: service)

    result = runner.invoke(cli.app, ["show", "CVE-2024-1111"])

    assert result.exit_code == 1
    assert "Traceback" not in result.output
    assert kev_calls == []
    assert epss_calls == []


def test_e2e_cached_result_then_forced_refresh(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_temp_cache(monkeypatch, tmp_path)
    nvd_bodies = [
        _load_fixture("nvd", "success_full.json"),
        _load_fixture("nvd", "success_partial.json"),
    ]
    call_counts = {"nvd": 0, "kev": 0, "epss": 0}

    def nvd_handler(request: httpx.Request) -> httpx.Response:
        index = min(call_counts["nvd"], len(nvd_bodies) - 1)
        call_counts["nvd"] += 1
        return httpx.Response(200, json=nvd_bodies[index])

    def kev_handler(request: httpx.Request) -> httpx.Response:
        call_counts["kev"] += 1
        return httpx.Response(200, json=_load_fixture("kev", "catalog.json"))

    def epss_handler(request: httpx.Request) -> httpx.Response:
        call_counts["epss"] += 1
        return httpx.Response(200, json=_load_fixture("epss", "success.json"))

    service = _build_correlation_service(nvd_handler, kev_handler, epss_handler)
    monkeypatch.setattr(cli, "build_correlation_service", lambda: service)

    # First call: cache miss, populates the cache.
    first = runner.invoke(cli.app, ["show", "CVE-2024-1111"])
    assert first.exit_code == 0
    assert call_counts == {"nvd": 1, "kev": 1, "epss": 1}

    # Second call: cache hit, no new HTTP calls, identical output.
    second = runner.invoke(cli.app, ["show", "CVE-2024-1111"])
    assert second.exit_code == 0
    assert call_counts == {"nvd": 1, "kev": 1, "epss": 1}
    assert second.output == first.output

    # Third call: --refresh forces a genuine re-fetch reflecting new data.
    third = runner.invoke(cli.app, ["show", "CVE-2024-1111", "--refresh"])
    assert third.exit_code == 0
    assert call_counts == {"nvd": 2, "kev": 2, "epss": 2}
    assert third.output != first.output
