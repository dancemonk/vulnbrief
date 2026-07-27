# Normalized Vulnerability Data Model

## Status

This is the planned semantic contract for the Pydantic model governed by the
model implementation Issue. No model exists yet. Implementers may choose class
names, but changing these meanings requires an Issue and documentation update.

## Briefing Fields

| Field | Planned type | Required | Source | Missing-data behavior |
|---|---|---:|---|---|
| `cve_id` | `str` | yes | validated input/NVD | Never omitted; uppercase `CVE-YYYY-NNNN...` |
| `description` | `str \| None` | no | NVD | `None` when legitimately absent |
| `published_at` | `datetime \| None` | no | NVD | `None` when source omits it |
| `modified_at` | `datetime \| None` | no | NVD | `None` when source omits it |
| `cvss` | `CvssInfo \| None` | no | NVD | `None` when no supported CVSS metric exists |
| `epss` | `EpssInfo \| None` | no | FIRST EPSS | `None` for no match or source failure; outcome explains which |
| `kev` | `KevInfo \| None` | no | CISA KEV | `None` when source failed; non-match represented explicitly |
| `references` | `list[Reference]` | yes | NVD/source metadata | Empty list when no references exist |
| `provenance` | `list[SourceProvenance]` | yes | all successful sources | Contains an entry for every incorporated source value |
| `source_outcomes` | `dict[SourceName, SourceOutcome]` | yes | adapters/service | Records every attempted source |
| `retrieved_at` | timezone-aware `datetime` | yes | application | UTC time for assembled result |

## Nested Values

`CvssInfo` contains score (`float | None`, 0–10), severity (`str | None`),
vector (`str | None`), and version (`str | None`). Unsupported or absent metrics
remain missing; they are not converted to zero.

`EpssInfo` contains score (`float`, 0–1), percentile (`float`, 0–1), and data
date (`date | None`). A zero probability is valid data and differs from a
missing score.

`KevInfo` contains `is_known_exploited` (`bool`), date added (`date | None`),
required action (`str | None`), remediation due date (`date | None`), known
ransomware-use status (`str | None`), and source URL (`str | None`). A successful
catalog lookup with no matching entry uses `is_known_exploited = false`; source
failure does not.

`Reference` contains a URL and optional label/source. `SourceProvenance`
identifies source, source URL when known, and retrieval timestamp.

## Source Outcomes

Each attempted source has one outcome:

- `found`: source responded and supplied matching data.
- `not_found`: source responded successfully but had no matching data.
- `unavailable`: timeout, rate limit, transport error, or service failure.
- `malformed`: response arrived but could not satisfy its source contract.

An absent field alone does not imply source failure. Consumers inspect both the
field and its source outcome. Expected errors may also carry a stable error code
for CLI messages and tests; raw response bodies must not enter domain models.

## Validation Principles

- Normalize CVE identifiers to uppercase after format validation.
- Use timezone-aware datetimes and preserve source-reported dates.
- Preserve legitimate zero and `false` values.
- Do not fabricate descriptions, dates, CVSS, EPSS, or KEV metadata.
- Keep source-specific response schemas inside adapters.
- Validate cached data through the same normalized model used for fresh data.

See [source contracts](source-contracts.md) for failure behavior.
