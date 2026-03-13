---
name: stalwart
description: Configure and manage the Stalwart JMAP server. Use when modifying JMAP settings, user provisioning, OAuth2 configuration, or admin API interactions.
---

# Stalwart

## Tool integration
- Use [references/config.md](./references/config.md) for the TOML configuration structure.
- Use [references/admin-api.md](./references/admin-api.md) for user provisioning and admin operations.
- Use [references/oauth2.md](./references/oauth2.md) for Stalwart's built-in OAuth2 server.

## Workflow
1. Review `stalwart/config.toml` before making changes.
2. Make changes and restart: `docker-compose restart stalwart`.
3. Verify with `docker compose logs stalwart` for startup errors.
4. Sync users if needed: `python3 scripts/sync_stalwart_users.py`.
5. Test JMAP endpoint at `http://localhost:8443/.well-known/jmap`.

## Guardrails
- Do not modify `stalwart-data/` directly — use the admin API or scripts.
- Do not change the admin password from `secret` without updating scripts.
- Do not expose Stalwart on public networks — this is a dev configuration.
- Do not mix Stalwart user management with Dovecot's `config/users` — they are separate stores.

## Done criteria
- Stalwart starts and passes healthcheck.
- JMAP session endpoint responds at `http://localhost:8443/.well-known/jmap`.
- Users are accessible via admin API.
