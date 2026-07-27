"""CVE identifier validation and normalization."""

import re

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


def normalize_cve_id(value: str) -> str:
    """Uppercase and validate a CVE identifier.

    Raises ValueError if the identifier does not match CVE-YYYY-NNNN... after
    uppercasing.
    """
    normalized = value.strip().upper()
    if not CVE_ID_PATTERN.match(normalized):
        raise ValueError(f"Invalid CVE identifier: {value!r}")
    return normalized
