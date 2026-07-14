# Public Safety Policy

## Purpose

Define what constitutes "public" vs "private" content for the CopyMarker repository and its public-safety scanner.

## Excluded from Public Repository

The following must never appear in tracked files, commit history, or CI artifacts:

### Personal Information

- Real names, usernames, or handles linked to real identity
- Real email addresses and conversations
- Phone numbers, addresses, government IDs
- Real copied text from user sessions

### Credentials and Authentication

- API keys, tokens, secrets, passwords
- Private keys (SSH, TLS, PGP, signing keys)
- OAuth tokens, JWTs, session cookies
- Database connection strings with credentials
- CI/CD tokens and deployment keys

### Browser and System Data

- Cookies and session data
- Browser profile paths and data
- Local absolute paths and usernames
- Private hostnames, IPs, domains, URLs, webhooks
- Internal operational instructions
- Internal prompts and agent-role text
- Real service HTML responses
- Personal screenshots

### Project-Specific

- Private project names and internal codenames
- Unreleased feature details
- Internal team communications

## Synthetic Fixtures Policy

Only clearly synthetic test data is permitted:

- Domains: `example.com`, `example.org`, `example.net`
- IP ranges: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`
- Emails: `user@example.com`, `test@example.org`
- Placeholder marker: `<redacted>`

## Private Denylist

Project-specific secret patterns are managed via `COPYMARKER_PRIVATE_DENYLIST_FILE` environment variable pointing to a local file (ignored by Git). The scanner loads this at runtime without printing terms or paths.

## Scanner Behavior

The public-safety scanner (`scripts/public-safety.mjs`):
- Scans tracked files via `git ls-files -z`
- Scans arbitrary paths via `--path`
- Reports only `RULE_ID relative/path:line`
- Never prints matched secret values
- Never prints private denylist terms or paths
- Exits nonzero on any violation

## Enforcement

- CI runs scanner on every push and PR
- Pre-commit hooks recommended locally
- Violations block merge
