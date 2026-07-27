# External Source Contracts

## Status and Common Interface

These contracts describe planned adapter behavior. No adapters or exception
classes exist yet. Each adapter accepts one validated, normalized CVE identifier
and returns normalized source data plus provenance, an explicit no-match result,
or a typed expected failure.

Adapters own source URLs, HTTPX usage, authentication configuration,
source-specific response models, and translation into domain values. They do
not render output, access SQLite, or import CLI modules.

## HTTP Requirements

- Every request uses an explicit finite timeout supplied through configuration
  or adapter construction. No implicit HTTPX default is accepted as policy.
- The numeric timeout remains undecided until the adapter Issues select and
  test it.
- Treat non-success status codes according to source behavior; never parse an
  error page as successful data.
- Rate limits produce a typed rate-limit failure and preserve safe retry timing
  metadata when supplied.
- v0.1 promises no automatic retries. Any future retry must be adapter-owned,
  bounded, limited to safe transient failures, respectful of `Retry-After`, and
  covered by deterministic tests.

## Expected Failures

Planned exception names are:

- `SourceTimeoutError`: request exceeded configured timeout.
- `SourceRateLimitError`: source refused the request because of rate limiting.
- `SourceUnavailableError`: transport or upstream availability failure.
- `SourceResponseError`: malformed JSON, schema mismatch, or unexpected status.
- `SourceNotFoundError`: primary record does not exist when absence prevents the
  requested operation.

Existing names take precedence once implementation exists. Error objects expose
safe source and category context, not credentials or full response bodies.

## Provenance and Partial Results

Successful adapter data includes source identity, source URL when known, and a
retrieval timestamp. The correlation service records outcomes for every
attempted source.

NVD failure prevents a complete briefing. CISA KEV or FIRST EPSS failure permits
a partial result when valid NVD data exists. A successful optional-source lookup
with no match is data, not an availability error.

## Source-Specific Expectations

### NVD

- Primary source for CVE identifier, description, timestamps, references, and
  available CVSS metrics.
- No matching CVE produces `SourceNotFoundError`.
- Timeout, rate limit, malformed JSON, and unexpected response structures map
  to their typed failures.
- API keys, when supported, come from environment-backed configuration and
  never appear in logs or fixtures.

### CISA Known Exploited Vulnerabilities

- Looks up the CVE in the KEV catalog.
- A successful catalog response without the CVE returns explicit
  `is_known_exploited = false` and `not_found` outcome.
- A match preserves date added, required action, remediation due date,
  ransomware-use status, and source URL when present.
- Missing optional catalog fields do not invalidate an otherwise usable match.

### FIRST EPSS

- Returns score, percentile, data date, and provenance for one CVE.
- Probability values normalize to numeric values between 0 and 1.
- A successful response without the CVE returns `not_found`, not a fabricated
  zero score.
- Timeout, rate limit, malformed JSON, and unexpected structures remain
  distinguishable.

## Tests and Fixtures

- Tests must never call live NVD, CISA, or FIRST services.
- Mock HTTPX at the transport/client boundary or use sanitized saved fixtures.
- Fixtures must cover success, no match, timeout, rate limit, malformed JSON,
  missing optional fields, and unexpected response shape.
- Assert explicit timeout configuration on every adapter request.
- Keep fixtures deterministic and document their source and capture date when
  derived from public data.
- Tests for correlation must cover complete data, each optional-source failure,
  primary-source failure, and multiple simultaneous optional failures.

See [architecture](architecture.md) and [data model](data-model.md).
