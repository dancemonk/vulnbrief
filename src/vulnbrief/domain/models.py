"""Normalized vulnerability domain models.

These models represent VulnBrief's internal vocabulary for a CVE briefing.
They must not depend on Typer, Rich, HTTPX, or SQLite (see
docs/architecture.md). Source adapters translate source-specific schemas into
these values; nothing here parses or knows about NVD/CISA/FIRST response
shapes.
"""

from datetime import date

from pydantic import AwareDatetime, BaseModel, ConfigDict, field_validator

from vulnbrief.domain.enums import SourceName, SourceOutcome
from vulnbrief.domain.identifiers import normalize_cve_id


class CvssInfo(BaseModel):
    """Available CVSS information for one CVE. Unsupported or absent metrics
    remain missing rather than being converted to zero."""

    model_config = ConfigDict(extra="forbid")

    score: float | None = None
    severity: str | None = None
    vector: str | None = None
    version: str | None = None

    @field_validator("score")
    @classmethod
    def validate_score_range(cls, value: float | None) -> float | None:
        if value is not None and not (0 <= value <= 10):
            raise ValueError("CVSS score must be between 0 and 10")
        return value


class EpssInfo(BaseModel):
    """EPSS score and percentile for one CVE. Only constructed when EPSS
    returned a match; a non-match or failure is represented by `epss=None`
    on the briefing plus the corresponding source outcome, not by this
    model with zero-filled fields."""

    model_config = ConfigDict(extra="forbid")

    score: float
    percentile: float
    data_date: date | None = None

    @field_validator("score", "percentile")
    @classmethod
    def validate_unit_range(cls, value: float) -> float:
        if not (0 <= value <= 1):
            raise ValueError("EPSS score and percentile must be between 0 and 1")
        return value


class KevInfo(BaseModel):
    """CISA KEV catalog status for one CVE. A successful catalog lookup with
    no matching entry is represented by `is_known_exploited=False`; source
    failure is represented by `kev=None` on the briefing instead."""

    model_config = ConfigDict(extra="forbid")

    is_known_exploited: bool
    date_added: date | None = None
    required_action: str | None = None
    due_date: date | None = None
    ransomware_use: str | None = None
    source_url: str | None = None


class Reference(BaseModel):
    """A single reference URL for a CVE."""

    model_config = ConfigDict(extra="forbid")

    url: str
    label: str | None = None
    source: str | None = None


class SourceProvenance(BaseModel):
    """Identifies where one incorporated value came from and when it was
    retrieved."""

    model_config = ConfigDict(extra="forbid")

    source: SourceName
    source_url: str | None = None
    retrieved_at: AwareDatetime


class VulnerabilityBriefing(BaseModel):
    """The normalized result of correlating NVD, CISA KEV, and FIRST EPSS
    data for one CVE."""

    model_config = ConfigDict(extra="forbid")

    cve_id: str
    description: str | None = None
    published_at: AwareDatetime | None = None
    modified_at: AwareDatetime | None = None
    cvss: CvssInfo | None = None
    epss: EpssInfo | None = None
    kev: KevInfo | None = None
    references: list[Reference] = []
    provenance: list[SourceProvenance] = []
    source_outcomes: dict[SourceName, SourceOutcome] = {}
    retrieved_at: AwareDatetime

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id(cls, value: str) -> str:
        return normalize_cve_id(value)
