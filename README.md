# VulnBrief

VulnBrief is a planned Python terminal application for retrieving, normalizing,
correlating, caching, and displaying vulnerability intelligence for one CVE.

## Project Status

VulnBrief now has an installable package and an empty Typer CLI (`vulnbrief
--help`), with pytest, Ruff, and mypy configured. The CLI has no commands yet —
no database, source adapters, or CVE retrieval/rendering exist. GitHub Issues
define the implementation sequence; documentation must not be read as evidence
that a planned feature already exists.

## Planned MVP

The v0.1 goal is one command:

```text
vulnbrief show CVE-YYYY-NNNN
```

See the [v0.1 specification](SPEC.md) for approved behavior and boundaries.

The command is planned to:

- retrieve CVE and CVSS data from NVD;
- check CISA Known Exploited Vulnerabilities status;
- retrieve FIRST EPSS probability data;
- normalize and correlate source results;
- cache successful briefings in SQLite; and
- render an explainable terminal briefing with Rich.

The configured foundation is Python 3.12, Typer, pytest, Ruff, mypy, uv, and
Hatchling. Rich, HTTPX, Pydantic, SQLite integration, and all source adapters
remain planned and are not implemented.

## Data Sources

- [NVD](https://nvd.nist.gov/) — primary CVE metadata and CVSS information.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) —
  known-exploitation status and remediation metadata.
- [FIRST EPSS](https://www.first.org/epss/) — exploitation probability and
  percentile.

## Development

```bash
uv sync --locked          # install dependencies into .venv from uv.lock
uv run vulnbrief --help   # run the CLI
make check                # lint, format-check, typecheck, test
```

For documentation-only changes, use:

```bash
git diff --check
git status --short
```

## Repository Structure

```text
AGENTS.md              Shared engineering and agent rules
CLAUDE.md              Claude Code-specific entry point
CONTRIBUTING.md        Contribution and review workflow
SECURITY.md            Security policy and reporting status
docs/                  Architecture, data, and source contracts
.github/                Issue and pull-request templates
pyproject.toml         Package metadata, Ruff, mypy, pytest configuration
.python-version        Declared supported Python version
Makefile               lint, format-check, typecheck, test, check targets
src/vulnbrief/         Installable package (CLI only so far)
tests/                 Test suite mirroring src/
```

Further application modules and tests will be added by their governing GitHub
Issues.

## Known Limitations

- The CLI exists but has no commands yet (no `show`, no CVE retrieval).
- No external-source adapter is implemented.
- No cache schema or normalized Pydantic model exists.
- CI runs `make check` on every pull request and push to `main` via GitHub
  Actions (`.github/workflows/ci.yml`).
- Confidential security reporting is not configured yet.

See [Contributing](CONTRIBUTING.md), [Security](SECURITY.md),
[Specification](SPEC.md), [Architecture](docs/architecture.md),
[Data Model](docs/data-model.md), and [Source Contracts](docs/source-contracts.md).
