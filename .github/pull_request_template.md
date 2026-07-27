# Pull Request

## Linked Issue

Closes #

## Summary

Describe the scoped outcome and why it is needed.

## Acceptance-Criteria Mapping

| Issue criterion | Change or evidence |
|---|---|
| | |

## Design Decisions

List meaningful choices, tradeoffs, ADR effects, or dependency changes. Write
`None` when no decision requires review.

## Changed Files

Summarize files or subsystems changed and their purpose.

## Verification

List every command exactly as executed and its result.

```text
command -> result
```

## Failure Scenarios Tested

List expected errors, missing-data cases, malformed inputs, and partial-source
failures covered.

## Security Considerations

Describe effects on secrets, untrusted external data, HTTP, logging, SQLite,
dependencies, or permissions. Write `None` only after review.

## Known Limitations

List remaining limitations or follow-up Issues.

## Review Focus

Point reviewers to risky assumptions, boundaries, or files needing close review.

## Checklist

- [ ] Scope matches the linked Issue.
- [ ] No unrelated refactoring is included.
- [ ] Tests were added or updated when behavior changed.
- [ ] Tests make no live external API calls.
- [ ] No secrets, API keys, `.env` files, or local databases are committed.
- [ ] All applicable configured checks pass.
- [ ] Unavailable or inapplicable checks are documented with a reason.
- [ ] `SPEC.md` was updated, or this change does not alter specified behavior.
- [ ] Relevant ADRs were updated, or no architecture decision changed.
- [ ] Documentation reflects user-visible and architectural changes.
- [ ] Failure scenarios and security effects were reviewed.
- [ ] No dependency was added without rationale and lockfile updates.
