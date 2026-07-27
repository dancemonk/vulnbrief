# Claude Code Instructions

@AGENTS.md
@SPEC.md

- Read the linked GitHub Issue and all comments before implementation.
- Start non-trivial work in plan mode.
- Map the plan directly to the Issue acceptance criteria.
- Identify affected files and tests before editing.
- Do not expand Issue scope or perform unrelated refactoring.
- Report conflicts between the Issue, `SPEC.md`, `AGENTS.md`, and ADRs before
  editing.
- Do not commit, push, or merge without explicit maintainer approval.
- Uses uv for dependency management.
- Commits uv.lock.
- Configures mypy.
- Adds Makefile targets for lint, format-check, typecheck, test, and check.
- `make check` passes.
- Declares and documents the supported Python version.
