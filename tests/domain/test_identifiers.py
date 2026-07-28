"""Validation tests for CVE identifier normalization."""

import pytest

from vulnbrief.domain.identifiers import InvalidCveIdError, normalize_cve_id


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CVE-2024-1234", "CVE-2024-1234"),
        ("cve-2024-1234", "CVE-2024-1234"),
        ("Cve-2024-1234", "CVE-2024-1234"),
        ("CVE-2024-123456789", "CVE-2024-123456789"),
        ("  CVE-2024-1234  ", "CVE-2024-1234"),
    ],
)
def test_normalize_cve_id_accepts_valid_ids(raw: str, expected: str) -> None:
    assert normalize_cve_id(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "CVE-2024-123",  # sequence number too short
        "CVE-24-1234",  # year not 4 digits
        "CVE-2024",  # missing sequence number
        "NVD-2024-1234",  # wrong prefix
        "CVE-2024-abcd",  # non-numeric sequence
        "CVE20241234",  # missing dashes
        "",
    ],
)
def test_normalize_cve_id_rejects_malformed_ids(raw: str) -> None:
    with pytest.raises(InvalidCveIdError):
        normalize_cve_id(raw)


def test_invalid_cve_id_error_is_still_a_value_error() -> None:
    # Pydantic only converts ValueError into ValidationError, so the base
    # class is load-bearing for VulnerabilityBriefing's cve_id validator.
    assert issubclass(InvalidCveIdError, ValueError)

    with pytest.raises(ValueError):
        normalize_cve_id("not-a-cve")
