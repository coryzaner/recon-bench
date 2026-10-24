# Security Policy

## Reporting a vulnerability

If you find a way to bypass the `recon-guard` safety gate (scope check,
signature check, expiry, acceptable-use check) or any other security issue,
please report it privately via the repository's private vulnerability
reporting / security advisory feature. Do not open a public issue for gate
bypasses. Include reproduction steps; we aim to acknowledge within 7 days.

## Scope of this project

- This bench is for testing systems **you own or are authorized in writing to
  test**. Reports about using it against third parties are out of scope.
- Never commit real `scope.yaml`, `authorization.yml`, `*.sig`, keys,
  inventories, or audit logs. `.gitignore` excludes them; double-check before
  pushing.
