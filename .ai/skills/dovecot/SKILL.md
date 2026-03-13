---
name: dovecot
description: Configure and administer the Dovecot IMAP server. Use when modifying authentication, mail storage, namespaces, SSL/TLS, logging, or LMTP settings.
---

# Dovecot

## Tool integration
- Use [references/config-files.md](./references/config-files.md) for the config file inventory and their purposes.
- Use [references/auth.md](./references/auth.md) for authentication mechanisms (passwd-file + OAuth2).
- Use [references/maildir-layout.md](./references/maildir-layout.md) for mail storage structure.
- Use [references/doveadm.md](./references/doveadm.md) for common `doveadm` commands.

## Workflow
1. Identify which config file(s) to modify from [references/config-files.md](./references/config-files.md).
2. Review the current file contents before editing.
3. Make changes and restart: `docker-compose restart dovecot`.
4. Verify with `docker compose logs dovecot` for startup errors.
5. Test with `doveadm` or an IMAP client connection.

## Guardrails
- Do not modify config files inside the container — edit the host `config/` directory.
- Do not change UID/GID mappings without updating `vmail/` ownership.
- Do not enable production-grade security settings — this is a dev environment.
- Do not remove `auth_debug = yes` — verbose logging is intentional for testing.

## Done criteria
- Dovecot starts without errors in logs.
- IMAP connections succeed on ports 143/993.
- Authentication works for users in `config/users`.
