# Contributing to VulnBrief

## Workflow

Every change follows one governing GitHub Issue:

```text
GitHub Issue
-> linked branch
-> implementation
-> local verification
-> independent review
-> pull request
-> CI
-> merge
```

Read the Issue and comments before planning. Keep acceptance criteria, failure
scenarios, and out-of-scope items visible throughout the work. Stop and report
conflicts instead of expanding scope.

Check [SPEC.md](SPEC.md) for approved product behavior. An Issue scopes work but
must not silently override the specification, repository rules, or an accepted
ADR. Behavior or architecture changes require maintainer-approved updates to
the affected shared document.

## Development Setup

```bash
uv sync                   # install dependencies into .venv
make check                # lint, format-check, typecheck, test
```

See [README.md](README.md#development) for the full command list.

## Branches and Commits

Use `<type>/<issue-number>-<short-slug>`, for example:

- `feat/4-nvd-adapter`
- `fix/15-timeout-handling`
- `docs/12-project-documentation-agent-workflow`

Keep commits focused. Use concise Conventional Commit subjects such as
`feat: add NVD adapter` or `docs: define source failures`. Do not commit, push,
merge, delete branches, or rewrite history without explicit maintainer
approval.

## Required Checks

Run `make check` before requesting review. It is the authoritative complete
verification command and covers formatting checks, linting, mypy, and pytest.

## Pull Requests

Pull requests must:

- link the governing Issue;
- map changes and tests to acceptance criteria;
- explain design or dependency decisions;
- list commands executed and exact results;
- cover relevant failure scenarios and security effects; and
- disclose known limitations and focused review requests.

Keep unrelated refactors in separate Issues and pull requests.

## Dependencies and Fixtures

Do not add a dependency without explaining why the standard library and current
dependencies are insufficient. Include maintenance, license, security, and
lockfile effects in the pull request.

Tests must never call live APIs. Use sanitized saved fixtures or mock HTTP at
the client boundary. Fixtures must contain no credentials, private reports, or
unnecessary personal data. SQLite tests must use temporary databases.

## Adding a Source Adapter

1. Create or use one Issue with source-specific acceptance criteria.
2. Follow [source contracts](docs/source-contracts.md) and the
   [source-adapter ADR](docs/decisions/0001-use-source-adapters.md).
3. Keep transport and source schema inside the adapter.
4. Convert results into normalized domain values before returning them.
5. Add fixture-backed tests for success, no match, timeout, rate limit,
   malformed data, and unexpected responses.
6. Update contracts only when behavior or assumptions change.

## Agent Roles

- **Claude Code:** primary implementation agent.
- **Codex:** independent reviewer, tester, debugger, planner, and secondary
  implementation agent.
- **Human maintainer:** scope, architecture, security, commit, merge, and release
  authority.

Two agents must not write to the same branch concurrently. Hand off through the
Issue, repository documents, committed code, and review comments—not private
chat history.
