# ADR 0001: Use Source Adapters

## Status

Accepted

## Context

NVD, CISA KEV, and FIRST EPSS expose different transports, schemas, update
patterns, and failure modes. Allowing those details into CLI, rendering,
storage, or shared domain code would couple the application to external schema
changes and make deterministic testing difficult.

## Decision

Isolate each external vulnerability source behind its own adapter. Every
adapter owns HTTP interaction and source-specific parsing, then converts its
result into normalized domain values before returning control to the
application service.

CLI, rendering, correlation, and storage consume normalized contracts only.
They must not parse or depend on source-specific JSON.

## Consequences

- **Testability:** adapters can use mocked transports and saved fixtures without
  live API calls.
- **Failure isolation:** source timeouts, rate limits, missing records, and
  malformed responses remain attributable and support partial results.
- **Maintainability:** source schema changes stay within one adapter and its
  tests.
- **Source replacement:** a source can be replaced while preserving the
  application-facing contract.
- **Schema independence:** domain models represent VulnBrief concepts instead
  of vendor response shapes.
- **Cost:** adapters require explicit translation code, fixtures, and contract
  tests.

See [architecture](../architecture.md) and
[source contracts](../source-contracts.md).
