"""SQLite implementation of BriefingRepository.

Uses only parameterized queries (AGENTS.md Security Rules). No cache TTL or
expiration policy is implemented here -- SPEC.md defers that to the `show`
workflow Issue.

sqlite3 and filesystem failures are translated into typed cache exceptions at
this boundary so backend details never reach the application or CLI layers.
Messages are deliberately generic: raw driver text and database paths are not
user-facing information.
"""

import sqlite3
from pathlib import Path
from types import TracebackType

from pydantic import ValidationError

from vulnbrief.domain.identifiers import normalize_cve_id
from vulnbrief.domain.models import VulnerabilityBriefing
from vulnbrief.storage.repository import CacheCorruptionError, CacheUnavailableError

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS briefings (
    cve_id TEXT PRIMARY KEY,
    data TEXT NOT NULL
)
"""

_UPSERT = """
INSERT INTO briefings (cve_id, data) VALUES (?, ?)
ON CONFLICT(cve_id) DO UPDATE SET data = excluded.data
"""

_SELECT = "SELECT data FROM briefings WHERE cve_id = ?"


class SqliteBriefingRepository:
    """Caches normalized vulnerability briefings in a local SQLite file."""

    def __init__(self, db_path: str | Path) -> None:
        path = Path(db_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(path)
            with self._connection:
                self._connection.execute(_CREATE_TABLE)
        except (sqlite3.Error, OSError) as exc:
            raise CacheUnavailableError("cache database could not be opened") from exc

    def get(self, cve_id: str) -> VulnerabilityBriefing | None:
        normalized_id = normalize_cve_id(cve_id)
        try:
            row = self._connection.execute(_SELECT, (normalized_id,)).fetchone()
        except sqlite3.Error as exc:
            raise CacheUnavailableError("cache database could not be read") from exc
        if row is None:
            return None
        try:
            return VulnerabilityBriefing.model_validate_json(row[0])
        except ValidationError as exc:
            raise CacheCorruptionError(
                f"cached record for {normalized_id} failed validation"
            ) from exc

    def put(self, briefing: VulnerabilityBriefing) -> None:
        data = briefing.model_dump_json()
        # `with self._connection:` commits on success and rolls back on error,
        # so a failed replacement leaves any existing record intact.
        try:
            with self._connection:
                self._connection.execute(_UPSERT, (briefing.cve_id, data))
        except sqlite3.Error as exc:
            raise CacheUnavailableError("cache database could not be written") from exc

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "SqliteBriefingRepository":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
