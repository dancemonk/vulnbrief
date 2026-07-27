"""Tests for SqliteBriefingRepository. All databases are temporary
(pytest's tmp_path fixture) -- never a contributor's local database."""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnbrief.domain.enums import SourceName, SourceOutcome
from vulnbrief.domain.models import (
    CvssInfo,
    EpssInfo,
    KevInfo,
    Reference,
    SourceProvenance,
    VulnerabilityBriefing,
)
from vulnbrief.storage.repository import CacheCorruptionError
from vulnbrief.storage.sqlite import SqliteBriefingRepository

CVE_ID = "CVE-2024-1234"
RETRIEVED_AT = datetime(2026, 1, 1, 12, 30, tzinfo=UTC)


def _full_briefing(
    cve_id: str = CVE_ID, description: str = "Example vulnerability."
) -> VulnerabilityBriefing:
    return VulnerabilityBriefing(
        cve_id=cve_id,
        description=description,
        published_at=datetime(2024, 1, 1, tzinfo=UTC),
        modified_at=datetime(2024, 2, 1, tzinfo=UTC),
        cvss=CvssInfo(score=7.5, severity="HIGH", vector="AV:N", version="3.1"),
        epss=EpssInfo(score=0.42, percentile=0.9),
        kev=KevInfo(is_known_exploited=True, required_action="Patch now."),
        references=[Reference(url="https://example.com/advisory")],
        provenance=[
            SourceProvenance(source=SourceName.NVD, retrieved_at=RETRIEVED_AT),
            SourceProvenance(source=SourceName.CISA_KEV, retrieved_at=RETRIEVED_AT),
            SourceProvenance(source=SourceName.FIRST_EPSS, retrieved_at=RETRIEVED_AT),
        ],
        source_outcomes={
            SourceName.NVD: SourceOutcome.FOUND,
            SourceName.CISA_KEV: SourceOutcome.FOUND,
            SourceName.FIRST_EPSS: SourceOutcome.FOUND,
        },
        retrieved_at=RETRIEVED_AT,
    )


def test_automatic_database_creation_in_nested_missing_directory(tmp_path: Path) -> None:
    db_path = tmp_path / "nested" / "dir" / "cache.db"
    assert not db_path.parent.exists()

    repo = SqliteBriefingRepository(db_path)

    assert db_path.exists()
    assert repo.get(CVE_ID) is None
    repo.close()


def test_insert_and_retrieve_complete_briefing(tmp_path: Path) -> None:
    repo = SqliteBriefingRepository(tmp_path / "cache.db")
    briefing = _full_briefing()

    repo.put(briefing)
    retrieved = repo.get(CVE_ID)

    assert retrieved is not None
    assert retrieved.cve_id == CVE_ID
    assert retrieved.description == briefing.description
    assert retrieved.cvss == briefing.cvss
    assert retrieved.epss == briefing.epss
    assert retrieved.kev == briefing.kev
    assert retrieved.references == briefing.references
    repo.close()


def test_missing_cve_returns_none(tmp_path: Path) -> None:
    repo = SqliteBriefingRepository(tmp_path / "cache.db")

    assert repo.get("CVE-2099-9999") is None
    repo.close()


def test_replacing_existing_record_returns_latest_data(tmp_path: Path) -> None:
    repo = SqliteBriefingRepository(tmp_path / "cache.db")
    repo.put(_full_briefing(description="Original description."))

    repo.put(_full_briefing(description="Updated description."))
    retrieved = repo.get(CVE_ID)

    assert retrieved is not None
    assert retrieved.description == "Updated description."
    repo.close()


def test_provenance_and_retrieval_time_are_preserved(tmp_path: Path) -> None:
    repo = SqliteBriefingRepository(tmp_path / "cache.db")
    briefing = _full_briefing()

    repo.put(briefing)
    retrieved = repo.get(CVE_ID)

    assert retrieved is not None
    assert len(retrieved.provenance) == 3
    assert {p.source for p in retrieved.provenance} == {
        SourceName.NVD,
        SourceName.CISA_KEV,
        SourceName.FIRST_EPSS,
    }
    assert retrieved.retrieved_at == RETRIEVED_AT
    assert retrieved.retrieved_at.tzinfo is not None
    repo.close()


def test_corrupted_serialized_data_raises_cache_corruption_error(tmp_path: Path) -> None:
    db_path = tmp_path / "cache.db"
    repo = SqliteBriefingRepository(db_path)
    repo.close()

    # Insert non-JSON garbage directly, bypassing the repository's own put().
    raw = sqlite3.connect(db_path)
    with raw:
        raw.execute(
            "INSERT INTO briefings (cve_id, data) VALUES (?, ?)",
            (CVE_ID, "not valid json{"),
        )
    raw.close()

    repo2 = SqliteBriefingRepository(db_path)
    with pytest.raises(CacheCorruptionError):
        repo2.get(CVE_ID)
    repo2.close()


def test_invalid_cached_model_data_raises_cache_corruption_error(tmp_path: Path) -> None:
    db_path = tmp_path / "cache.db"
    repo = SqliteBriefingRepository(db_path)
    repo.close()

    # Valid JSON, but missing required fields for VulnerabilityBriefing.
    raw = sqlite3.connect(db_path)
    with raw:
        raw.execute(
            "INSERT INTO briefings (cve_id, data) VALUES (?, ?)",
            (CVE_ID, '{"unexpected": "shape"}'),
        )
    raw.close()

    repo2 = SqliteBriefingRepository(db_path)
    with pytest.raises(CacheCorruptionError):
        repo2.get(CVE_ID)
    repo2.close()


def test_failed_write_does_not_destroy_existing_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = SqliteBriefingRepository(tmp_path / "cache.db")
    original = _full_briefing(description="Original description.")
    repo.put(original)

    # Force a genuine SQL failure mid-write (targeting a nonexistent table)
    # to exercise the real commit/rollback behavior of `with self._connection:`
    # rather than mocking it away.
    monkeypatch.setattr(
        "vulnbrief.storage.sqlite._UPSERT",
        "INSERT INTO nonexistent_table (cve_id, data) VALUES (?, ?)",
    )
    with pytest.raises(sqlite3.OperationalError):
        repo.put(_full_briefing(description="Attempted update."))
    monkeypatch.undo()

    retrieved = repo.get(CVE_ID)
    assert retrieved is not None
    assert retrieved.description == "Original description."
    repo.close()


def test_sql_like_text_in_description_round_trips_safely(tmp_path: Path) -> None:
    repo = SqliteBriefingRepository(tmp_path / "cache.db")
    dangerous_description = "O'Brien's vuln'; DROP TABLE briefings; --"
    briefing = _full_briefing(description=dangerous_description)

    repo.put(briefing)
    retrieved = repo.get(CVE_ID)

    assert retrieved is not None
    assert retrieved.description == dangerous_description
    # The table must still exist and be queryable -- proves the value was
    # bound as a parameter, never string-interpolated into the SQL text.
    assert repo.get("CVE-2099-9999") is None
    repo.close()


def test_case_insensitive_lookup_matches_normalized_cve_id(tmp_path: Path) -> None:
    repo = SqliteBriefingRepository(tmp_path / "cache.db")
    repo.put(_full_briefing())

    retrieved = repo.get("cve-2024-1234")

    assert retrieved is not None
    assert retrieved.cve_id == CVE_ID
    repo.close()


def test_temporary_database_isolation_between_repository_instances(tmp_path: Path) -> None:
    repo_a = SqliteBriefingRepository(tmp_path / "a.db")
    repo_b = SqliteBriefingRepository(tmp_path / "b.db")

    repo_a.put(_full_briefing())

    assert repo_a.get(CVE_ID) is not None
    assert repo_b.get(CVE_ID) is None
    repo_a.close()
    repo_b.close()


def test_context_manager_closes_connection(tmp_path: Path) -> None:
    db_path = tmp_path / "cache.db"
    with SqliteBriefingRepository(db_path) as repo:
        repo.put(_full_briefing())
        assert repo.get(CVE_ID) is not None

    with pytest.raises(sqlite3.ProgrammingError):
        repo.get(CVE_ID)
