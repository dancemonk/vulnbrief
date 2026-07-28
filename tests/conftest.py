"""Suite-wide test isolation.

SPEC.md V8 and AGENTS.md require that tests never reach live external services
and never touch a contributor's real cache database. Both were previously
guaranteed only by every test author remembering to inject a mock transport
and a temporary database path. These autouse fixtures make the guarantee
structural, so a forgotten mock fails loudly instead of silently calling NVD,
CISA, or FIRST.
"""

import socket
from pathlib import Path

import pytest


class BlockedNetworkAccessError(RuntimeError):
    """Raised when a test attempts a real network connection.

    Deliberately not an OSError: httpx converts OSError into
    httpx.ConnectError, and application code catches OSError in places, so an
    OSError-based guard could be swallowed by the code under test and hide the
    very thing it exists to reveal.
    """


@pytest.fixture(autouse=True)
def block_network_access(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any test that opens a real TCP connection.

    Patching socket.socket is the lowest common layer: httpx, httpcore, and
    anyio all bottom out there, so injected httpx.MockTransport instances and
    fake adapters are unaffected.
    """

    def guard(self: socket.socket, address: object, *args: object) -> None:
        raise BlockedNetworkAccessError(
            f"test attempted a real network connection to {address!r}; "
            "inject an httpx.MockTransport or a fake instead"
        )

    monkeypatch.setattr(socket.socket, "connect", guard)
    monkeypatch.setattr(socket.socket, "connect_ex", guard)


@pytest.fixture(autouse=True)
def temporary_cache_database(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Point the cache at a per-test temporary database.

    A test that constructs the real repository without setting this would
    otherwise read and write the contributor's own ~/.vulnbrief/cache.db.
    Tests that set VULNBRIEF_DB_PATH themselves still override this, since
    the fixture runs first.
    """
    monkeypatch.setenv("VULNBRIEF_DB_PATH", str(tmp_path / "cache.db"))
