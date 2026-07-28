"""CVE identifier validation and normalization."""

import re

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


class InvalidCveIdError(ValueError):
    """A CVE identifier is not in CVE-YYYY-NNNN... form.

    Subclasses ValueError deliberately: VulnerabilityBriefing validates its
    cve_id through normalize_cve_id, and Pydantic only converts ValueError
    into ValidationError. It exists so callers can distinguish bad user input
    from an internal parsing or validation ValueError.
    """


def normalize_cve_id(value: str) -> str:
    """Uppercase and validate a CVE identifier.

    Raises InvalidCveIdError if the identifier does not match
    CVE-YYYY-NNNN... after uppercasing.
    """
    normalized = value.strip().upper()
    if not CVE_ID_PATTERN.match(normalized):
        raise InvalidCveIdError(f"Invalid CVE identifier: {value!r}")
    return normalized
