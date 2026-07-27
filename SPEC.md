# VulnBrief v0.1 Specification

> Status: planned. No application code currently exists. This specification
> defines approved v0.1 requirements, not implemented behavior.

## §G Goal

Help a security-aware developer or analyst retrieve one explainable
vulnerability briefing in a terminal:

```text
vulnbrief show CVE-YYYY-NNNN
```

The briefing combines normalized NVD, CISA KEV, and FIRST EPSS intelligence
while preserving source provenance and making missing or failed enrichment
visible.

## §C Constraints

- Accept one CVE identifier, validate its shape, and normalize accepted input.
- Check the SQLite cache before external sources. `--refresh` bypasses cached
  data. Do not define a cache TTL until its governing Issue approves one.
- NVD is required. A missing NVD record or NVD failure prevents a complete
  briefing.
- CISA KEV and FIRST EPSS are optional enrichments. Their failure must not
  discard valid NVD data.
- Distinguish a successful source response with no match from timeout, rate
  limit, unavailability, malformed data, or another source failure.
- Normalize source data before application, storage, or rendering use. Preserve
  source identity, source URL when known, and retrieval time.
- Successful normalized retrievals may be cached; `--refresh` replaces usable
  cached data only after successful retrieval.
- Do not invent missing values. Legitimate zero, `false`, and absent values stay
  distinct.
- Tests use fixtures or mocked HTTP and never call live external APIs.
- Every HTTP request uses an explicit finite timeout; this specification does
  not choose a numeric value.

## §I Interfaces

### I.cli — command input

`vulnbrief show CVE-YYYY-NNNN` accepts one required CVE identifier and an
optional `--refresh` flag. Invalid identifiers fail clearly without a Python
traceback. Exit-code numbers are not specified.

### I.briefing — normalized result

The result carries CVE identifier, description, published and modified times,
available CVSS information, EPSS score and percentile, KEV status and available
KEV metadata, references, provenance, retrieval time, and per-source outcomes.
Detailed planned field semantics live in [data model](docs/data-model.md).

### I.sources — source behavior

- **NVD:** required primary CVE metadata and available CVSS information.
- **CISA KEV:** optional known-exploitation status, required action, and due date
  when available.
- **FIRST EPSS:** optional exploitation score and percentile when available.

Adapters follow [source contracts](docs/source-contracts.md).

### I.output — terminal briefing

Display CVE ID, description, publication and modification dates, available CVSS
score/severity/vector, available EPSS score/percentile, KEV status and metadata,
and source provenance. Missing values and partial-source failures remain clear.
Output stays understandable without color and handles long descriptions and
narrow terminals reasonably.

### I.errors — expected categories

Expected categories are invalid input, CVE not found, timeout, rate limit,
source unavailable, malformed or unexpected source response, and cache
read/corruption failure. User-facing errors are understandable and hide
tracebacks by default. Class names and numeric exit codes remain implementation
decisions for their governing Issues.

## §V Invariants

- **V1:** CLI delegates retrieval; it performs no HTTP and parses no
  source-specific JSON.
- **V2:** Source-specific schemas stay inside adapters; shared consumers receive
  normalized domain values.
- **V3:** Domain models depend on no Typer, Rich, HTTPX, or SQLite details.
- **V4:** Rendering accesses no adapter, HTTP client, or storage implementation.
- **V5:** Storage remains behind a repository contract and contains no
  presentation logic.
- **V6:** NVD failure prevents a complete result; KEV or EPSS failure preserves
  valid NVD data with explicit partial-source status.
- **V7:** No-match and source-failure states remain distinguishable.
- **V8:** Tests perform no live external API requests and use temporary SQLite
  databases.
- **V9:** Every HTTP request has an explicit finite timeout.
- **V10:** No secrets, `.env` files, or local databases enter version control.

## §T Planned Implementation

| id | status | task | cites |
|---|---|---|---|
| T1 | . | Bootstrap package and empty CLI (Issue #2) | I.cli,V10 |
| T2 | . | Create normalized vulnerability model (Issue #3) | I.briefing,V2,V3,V7 |
| T3 | . | Implement NVD adapter (Issue #4) | I.sources,V2,V6,V7,V9 |
| T4 | . | Implement CISA KEV adapter (Issue #5) | I.sources,V2,V6,V7,V9 |
| T5 | . | Implement FIRST EPSS adapter (Issue #6) | I.sources,V2,V6,V7,V9 |
| T6 | . | Correlate source results (Issue #7) | I.briefing,V6,V7 |
| T7 | . | Add SQLite cache repository (Issue #8) | I.briefing,V5,V8,V10 |
| T8 | . | Implement `vulnbrief show` workflow (Issue #9) | I.cli,I.errors,V1,V6 |
| T9 | . | Render Rich terminal briefing (Issue #10) | I.output,V4 |
| T10 | . | Add CI and end-to-end tests (Issue #11) | I.cli,I.output,V8 |

## v0.1 Out of Scope

- Bulk lookup, search, synchronization, watchlists, or scheduled retrieval
- Security news, vendor advisory aggregation, or historical EPSS tracking
- Web interfaces, accounts, cloud hosting, deployment, or package publishing
- AI-generated summaries, custom risk scores, or automated remediation
- Interactive terminal dashboards, charts, or themes
- Cache migration framework, full-text search, or historical snapshots

## Definition of Done

v0.1 is done when one valid CVE can complete the cache-aware `show` workflow;
required and optional source behavior follows this specification; normalized
provenance and partial results render clearly; expected failures produce useful
messages; tests cover success, missing data, cache, refresh, and source failures
without live APIs; and all configured formatting, lint, type, test, and CI
checks pass.

## §B Backprop History

| id | date | cause | fix |
|---|---|---|---|
