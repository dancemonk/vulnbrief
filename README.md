# VulnBrief

VulnBrief is a Python terminal application that retrieves, normalizes,
correlates, caches, and displays vulnerability intelligence for one CVE.

## Project Status

The v0.1 MVP is implemented. `vulnbrief show CVE-YYYY-NNNN` retrieves CVE and
CVSS data from NVD, checks the CISA Known Exploited Vulnerabilities catalog,
retrieves FIRST EPSS probability data, correlates the results into one
normalized briefing, caches it in SQLite, and renders it with Rich.

GitHub Actions runs lint, formatting, strict type checking, and the full test
suite on every pull request and every push to `main`.

## Usage

```bash
uv run vulnbrief show CVE-2021-44228              # cache-first lookup
uv run vulnbrief show CVE-2021-44228 --refresh    # bypass cache, refetch
uv run vulnbrief --help
uv run vulnbrief show --help
```

One CVE identifier per invocation. Identifiers are case-insensitive:
`cve-2021-44228` is normalized to `CVE-2021-44228`.

### What each source contributes

- [NVD](https://nvd.nist.gov/) — description, publication and modification
  dates, references, and available CVSS metrics. **Required:** if NVD is
  unavailable or has no record, no briefing is produced.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) —
  known-exploitation status, required action, and remediation due date.
  Optional enrichment.
- [FIRST EPSS](https://www.first.org/epss/) — exploitation probability and
  percentile. Optional enrichment.

### Partial results

A failure in an optional source never discards valid NVD data. The briefing is
still rendered, and the source table records what happened to each source, so
"not in the KEV catalog" stays distinguishable from "CISA could not be
reached" and from "not checked".

### Example output

Illustrative only — not a verbatim capture. Actual values depend on the CVE
and on what each source returns at the time of the lookup.

```text
╭────────────────────────────── CVE-2021-44228 ───────────────────────────────╮
│ Apache Log4j2 JNDI features do not protect against attacker controlled      │
│ LDAP and other JNDI related endpoints.                                      │
│ Published: 2021-12-10T10:15:09+00:00   Modified: 2025-04-03T01:03:51+00:00  │
│ CVSS 10.0, CRITICAL, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H           │
│ EPSS 0.944 (0.99 percentile)                                                │
│ KEV  Known Exploited (added 2021-12-10, action: Apply updates., due ...)    │
│ References:                                                                 │
│ - https://logging.apache.org/log4j/2.x/security.html                        │
│                                  Sources                                    │
│  NVD         Found   2026-07-27T12:00:00+00:00                              │
│  CISA KEV    Found   2026-07-27T12:00:00+00:00                              │
│  FIRST EPSS  Found   2026-07-27T12:00:00+00:00                              │
╰─────────────────────────────────────────────────────────────────────────────╯
```

Output remains readable without color and handles narrow terminals.

## Configuration

| Variable | Purpose |
|---|---|
| `NVD_API_KEY` | Optional. Sent as NVD's `apiKey` header; raises NVD's rate limit. Lookups work without it. |
| `VULNBRIEF_DB_PATH` | Optional. Overrides the cache database location. |

The cache defaults to `~/.vulnbrief/cache.db`, created on first use. It holds
only normalized public CVE data. There is no TTL — `--refresh` is the only way
to invalidate an entry. A briefing whose optional sources failed is not reused
from cache; the next lookup retries them.

If the cache file cannot be opened, the lookup still runs against live sources
and a warning is printed; results simply are not cached for that run.

## Installation

```bash
uv sync --locked          # install dependencies exactly from uv.lock
uv run vulnbrief --help
```

Requires Python 3.12 or newer.

## Development

```bash
uv sync --locked          # install dependencies into .venv from uv.lock
make lint                 # Ruff lint checks
make format-check         # Ruff formatting check
make typecheck            # strict mypy
make test                 # pytest
make check                # all of the above; the authoritative command
```

Tests never contact live services. An autouse fixture blocks real network
connections and points the cache at a temporary database, so a forgotten mock
fails loudly instead of reaching NVD, CISA, or FIRST.

## Repository Structure

```text
AGENTS.md                     Shared engineering and agent rules
CLAUDE.md                     Claude Code entry point
CONTRIBUTING.md               Contribution and review workflow
SECURITY.md                   Security policy and reporting status
SPEC.md                       Approved v0.1 behavior and boundaries
docs/                         Architecture, data model, source contracts, ADRs
.github/workflows/ci.yml      Lint, format, typecheck, and test on PR and main
pyproject.toml                Package, Ruff, mypy, and pytest configuration
Makefile                      lint, format-check, typecheck, test, check
src/vulnbrief/
  cli.py                      Typer CLI; validates input and delegates
  workflow.py                 Cache-first lookup and best-effort save
  correlation.py              Merges source results into one briefing
  rendering.py                Rich terminal output
  adapters/                   NVD, CISA KEV, FIRST EPSS; HTTP and source schemas
  domain/                     Normalized models, enums, identifier validation
  storage/                    SQLite cache behind a repository interface
tests/                        Test suite mirroring src/
```

## Known Limitations

- No cache expiry. `--refresh` is the only way to invalidate a cached briefing.
- One CVE per invocation. Bulk lookup and search are out of scope for v0.1.
- No automatic retries. A timeout or rate limit is reported, not retried.
- Each KEV lookup downloads the full catalog; there is no local KEV cache
  independent of the briefing cache.
- Confidential security reporting is not configured yet (see
  [SECURITY.md](SECURITY.md)).

## Out of Scope for v0.1

Bulk lookup, search, synchronization, watchlists, scheduled retrieval, security
news or vendor advisory aggregation, historical EPSS tracking, web interfaces,
accounts, cloud hosting, package publishing, AI-generated summaries, custom
risk scores, and interactive dashboards are not implemented and are not planned
for v0.1.

See [Contributing](CONTRIBUTING.md), [Security](SECURITY.md),
[Specification](SPEC.md), [Architecture](docs/architecture.md),
[Data Model](docs/data-model.md), and [Source Contracts](docs/source-contracts.md).
