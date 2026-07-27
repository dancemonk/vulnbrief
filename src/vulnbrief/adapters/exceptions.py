"""Typed expected-failure exceptions for vulnerability source adapters.

Shared across all source adapters (NVD, CISA KEV, FIRST EPSS) per
docs/source-contracts.md. Error messages carry safe source/category context
only -- never credentials, API keys, or raw response bodies.
"""

from vulnbrief.domain.enums import SourceName


class SourceError(Exception):
    """Base class for expected source-adapter failures."""

    def __init__(self, source: SourceName, message: str) -> None:
        self.source = source
        super().__init__(f"[{source.value}] {message}")


class SourceTimeoutError(SourceError):
    """Request exceeded the configured timeout."""


class SourceRateLimitError(SourceError):
    """Source refused the request because of rate limiting."""

    def __init__(self, source: SourceName, message: str, retry_after: str | None = None) -> None:
        self.retry_after = retry_after
        super().__init__(source, message)


class SourceUnavailableError(SourceError):
    """Transport or upstream availability failure."""


class SourceResponseError(SourceError):
    """Malformed JSON, schema mismatch, or unexpected response status."""


class SourceNotFoundError(SourceError):
    """The requested primary record does not exist at the source."""
