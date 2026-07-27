# Repository Guidelines

## Purpose and Current State

VulnBrief is planned as a Python terminal application that retrieves,
normalizes, correlates, caches, and displays vulnerability intelligence from
NVD, CISA KEV, and FIRST EPSS. The repository is currently a documentation
scaffold: no package, CLI, database, or tests exist yet. Treat capabilities in
GitHub Issues and `docs/` as planned until implementation and tests exist.

## Source of Truth

Use this order:

1. GitHub Issue acceptance criteria
2. `AGENTS.md`
3. Accepted architecture decision records
4. Architecture and source contracts
5. Existing tests
6. Existing implementation
7. Agent assumptions

When sources conflict, report the conflict. Never silently choose one.

## Repository Structure

- `README.md`: product status, planned MVP, and contributor entry points.
- `CONTRIBUTING.md`: Issue, branch, review, and pull-request workflow.
- `SECURITY.md`: security policy and reporting status.
- `docs/architecture.md`: layer responsibilities and dependency rules.
- `docs/data-model.md`: planned normalized vulnerability semantics.
- `docs/source-contracts.md`: common and source-specific adapter behavior.
- `docs/decisions/`: accepted architecture decision records.
- `.github/`: Issue forms and pull-request template.

Future production code belongs under `src/`; tests mirror it under `tests/`.
Do not add root-level implementation modules.

## Architecture Boundaries

Follow [architecture](docs/architecture.md) and accepted ADRs.

- CLI code validates input and delegates; it must not perform HTTP requests or
  parse source-specific JSON.
- Source adapters own HTTP and translate source schemas into normalized domain
  values. Source-specific schemas must not leak into domain models.
- Domain models must remain independent of Typer, Rich, HTTPX, and SQLite.
- Rendering code must not access HTTP clients, adapters, or the database.
- Storage must be isolated behind a repository interface.
- Storage code must not contain presentation logic.
- Use typed exceptions for expected source failures.

## Development Commands

No Python toolchain is configured yet. Current repository checks are:

```bash
git diff --check
git status --short
```

Do not invent or claim working commands. When a `Makefile` with a valid
`check` target exists, `make check` becomes the required complete verification
command. Until then, run every documented available check and report missing
lint, type-check, and test commands explicitly.

## Coding Rules

- Work on one GitHub Issue at a time. Map every change to its acceptance
  criteria.
- Do not perform unrelated refactoring or expand scope.
- Do not add dependencies without explaining need and tradeoffs in the Issue or
  pull request. Commit the uv lockfile when dependency management exists.
- Use UTF-8, Unix line endings, and spaces. Use Python type annotations once
  Python code exists; Ruff and mypy will define enforceable style.
- Prefer small, purpose-focused modules and explicit interfaces.
- Update user and architecture documentation when behavior or boundaries
  change.

## Testing Rules

- Tests must never call live external APIs.
- Mock HTTP at the client boundary or use sanitized, deterministic fixtures.
- Use temporary SQLite databases; never use a contributor's local database.
- Add unit tests for new behavior and regression tests for every bug fix.
- Cover success, missing data, malformed responses, timeouts, rate limits, and
  relevant partial-source failures.
- Keep tests deterministic and independent of network access, API keys, clock,
  and execution order.

## HTTP and External Sources

- Every HTTP request must use an explicit finite timeout.
- Keep HTTP clients inside source adapters; inject clients or transports for
  tests.
- Follow [source contracts](docs/source-contracts.md) for rate limits, retries,
  provenance, and typed failures.
- Distinguish source success with no match from timeout, unavailability, and
  malformed data.
- Never discard valid primary data solely because an optional source failed.

## Security Rules

- Never commit secrets, API keys, `.env` files, local databases, private
  vulnerability reports, or sensitive logs.
- Treat external descriptions, URLs, and metadata as untrusted input. Escape or
  safely render them; never execute embedded content.
- Use parameterized SQLite queries only.
- Do not log credentials, full HTTP authorization headers, or unnecessary
  response bodies.
- Review dependency changes for maintenance, license, and supply-chain risk.

## Git and GitHub Workflow

- Use a linked branch for the governing Issue; follow
  [CONTRIBUTING.md](CONTRIBUTING.md).
- Keep commits focused and use Conventional Commit subjects such as
  `docs: clarify source failures` or `feat: add NVD adapter`.
- Do not commit, push, merge, delete branches, or rewrite history without
  explicit maintainer approval.
- Two agents must not write to the same branch concurrently.
- Pull requests must link the Issue and map changes and tests to acceptance
  criteria.

## Definition of Done

A task is done only when scope matches its Issue, implementation and docs agree,
tests cover behavior and failures, no live API calls occur in tests, security
rules hold, and the repository's complete verification command passes. If that
command does not exist, state the gap; never report success for checks not run.

## Required Completion Report

Report:

1. Files created, updated, and intentionally unchanged
2. Acceptance criteria satisfied
3. Commands executed with exact results
4. Tests added or updated
5. Assumptions and source conflicts
6. Remaining risks and follow-up Issues
7. Git status, with confirmation that no unapproved commit or push occurred
