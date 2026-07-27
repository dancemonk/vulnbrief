"""Enumerations shared by normalized vulnerability domain models."""

from enum import StrEnum


class SourceName(StrEnum):
    """A vulnerability intelligence source consumed by VulnBrief."""

    NVD = "nvd"
    CISA_KEV = "cisa_kev"
    FIRST_EPSS = "first_epss"


class SourceOutcome(StrEnum):
    """The result of one attempted source lookup for a single CVE."""

    FOUND = "found"
    NOT_FOUND = "not_found"
    UNAVAILABLE = "unavailable"
    MALFORMED = "malformed"
