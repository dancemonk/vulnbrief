# Security Policy

## Supported Versions

VulnBrief is pre-release and has no supported release versions. Security fixes
currently target the latest `main` branch. A version-support table will be added
when releases begin.

## Reporting a Vulnerability

Private vulnerability reporting is not currently configured. Vulnerability
details must not be submitted through public Issues. A confidential channel
must be configured before private reports can be accepted.

Enabling GitHub private vulnerability reporting is a maintainer follow-up. No
security email address or alternative private contact channel is currently
available.

## Secrets and Configuration

- Keep API keys and credentials in environment variables when configuration is
  implemented.
- Never commit `.env` files, local databases, authorization headers, or private
  reports.
- Example configuration must use obvious placeholders.
- Tests and CI must run without production API keys.

## Logging and Untrusted Data

Log source name, operation, status, and safe diagnostic context. Do not log
credentials, full authorization headers, local database contents, or entire
external responses by default.

Treat vulnerability descriptions, references, vendor text, URLs, and all other
external-source content as untrusted data. Validate expected shapes, constrain
display behavior, and never execute embedded markup, commands, or code.

## Storage Safety

Use parameterized SQLite queries. Keep storage behind its repository interface,
validate deserialized cached data, and use temporary databases in tests. Never
delete or migrate contributor data without an explicit Issue, backup plan, and
maintainer approval.

## Dependencies and Supply Chain

Minimize dependencies. Review each addition for ownership, maintenance health,
license, transitive dependencies, and known vulnerabilities. Commit the uv
lockfile when dependency management exists, and keep local and CI installation
paths aligned.

## Known Limitations

- No application code or security test suite exists yet.
- External-source response validation is not implemented.
- Cache integrity and migration behavior are not implemented.
- Confidential vulnerability reporting is not configured.
- No release or dependency-scanning policy is active.
