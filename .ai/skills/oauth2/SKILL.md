---
name: oauth2
description: Configure and extend the mock OAuth2 authorization server. Use when modifying token introspection, authorization flows, or adding new OAuth2 endpoints.
---

# OAuth2

## Tool integration
- Use [references/endpoints.md](./references/endpoints.md) for the full endpoint inventory.
- Use [references/token-conventions.md](./references/token-conventions.md) for token format rules.
- Use [references/integration.md](./references/integration.md) for how services consume OAuth2.

## Workflow
1. Review `oauth2-mock/server.py` before making changes.
2. Rebuild: `docker-compose build oauth2-mock`.
3. Restart: `docker-compose up -d oauth2-mock`.
4. Test introspection: `curl -X POST http://localhost:8080/introspect -d 'token=valid-dev@local.test'`.
5. Verify Dovecot can still authenticate via OAuth2.

## Guardrails
- Do not add real security — any `client_id`/`client_secret` is accepted by design.
- Do not change the introspection response format without updating Dovecot's `10-auth.conf`.
- Do not remove the `/health` endpoint — it's used by the Docker healthcheck.
- Do not add external Python dependencies — the server uses stdlib only.

## Done criteria
- oauth2-mock starts and passes healthcheck.
- Introspection returns correct responses for token conventions.
- Dovecot OAuth2 authentication still works end-to-end.
