"""Storage repositories for cached vulnerability briefings."""

from vulnbrief.storage.null import NullBriefingRepository
from vulnbrief.storage.repository import (
    BriefingRepository,
    CacheCorruptionError,
    CacheError,
    CacheUnavailableError,
)
from vulnbrief.storage.sqlite import SqliteBriefingRepository

__all__ = [
    "BriefingRepository",
    "CacheCorruptionError",
    "CacheError",
    "CacheUnavailableError",
    "NullBriefingRepository",
    "SqliteBriefingRepository",
]
