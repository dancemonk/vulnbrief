"""Tests for the suite-wide isolation guards in conftest.py.

These prove the guards actually fire, rather than asserting that the fixtures
merely exist. Every connection attempted here is to a closed loopback port or
through a blocked client, so nothing leaves the machine.
"""

import os
import socket
from pathlib import Path

import httpx
import pytest

import vulnbrief.cli as cli
from vulnbrief.adapters import NvdAdapter

CLOSED_LOOPBACK_PORT = 9  # discard port, expected closed

# `tests` is not an importable package, so the guard exception is matched by
# its message rather than imported from conftest.
BLOCKED = "attempted a real network connection"


def test_raw_socket_connection_is_blocked() -> None:
    with pytest.raises(RuntimeError, match=BLOCKED):
        socket.create_connection(("127.0.0.1", CLOSED_LOOPBACK_PORT), timeout=1)


def test_unmocked_httpx_client_is_blocked() -> None:
    # The realistic failure this guards against: a test that forgets to inject
    # a transport and silently reaches a live service.
    with pytest.raises(RuntimeError, match=BLOCKED):
        httpx.Client(timeout=1).get(f"http://127.0.0.1:{CLOSED_LOOPBACK_PORT}/")


def test_adapter_constructed_without_transport_is_blocked() -> None:
    # Proves the guard covers real production client construction, not just
    # hand-rolled httpx usage in tests.
    adapter = NvdAdapter(timeout=1)

    with pytest.raises(RuntimeError, match=BLOCKED):
        adapter.get_cve("CVE-2024-1234")


def test_injected_mock_transport_still_works() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"mocked": True})

    client = httpx.Client(transport=httpx.MockTransport(handler))

    response = client.get("http://example.invalid/")

    assert response.status_code == 200
    assert response.json() == {"mocked": True}


def test_cache_path_is_temporary_and_not_the_user_database(tmp_path: Path) -> None:
    db_path = os.environ.get("VULNBRIEF_DB_PATH")

    assert db_path is not None
    assert db_path == str(tmp_path / "cache.db")
    assert Path(db_path).is_relative_to(tmp_path)
    assert Path(db_path) != cli.DEFAULT_DB_PATH


def test_real_repository_writes_only_under_tmp_path(tmp_path: Path) -> None:
    # build_repository() reads VULNBRIEF_DB_PATH, so the autouse fixture is
    # what keeps this off the contributor's real database.
    default_existed = cli.DEFAULT_DB_PATH.exists()

    repository = cli.build_repository()
    try:
        assert (tmp_path / "cache.db").exists()
        assert cli.DEFAULT_DB_PATH.exists() == default_existed  # nothing created outside tmp_path
    finally:
        repository.close()
