---
name: postfix
description: Configure the Postfix SMTP server for mail submission and LMTP delivery to Dovecot. Use when modifying SMTP settings, relay configuration, or mail routing.
---

# Postfix

## Tool integration
- Use [references/config.md](./references/config.md) for `main.cf` settings and entrypoint behavior.
- Use [references/mail-flow.md](./references/mail-flow.md) for the SMTP → LMTP delivery path.

## Workflow
1. Review `postfix/main.cf` and `postfix/entrypoint.sh` before changes.
2. Rebuild if Dockerfile changed: `docker-compose build postfix`.
3. Restart: `docker-compose restart postfix`.
4. Test with: `swaks --to dev@local.test --server localhost:1025` or equivalent.

## Guardrails
- Do not enable open relay settings — restrict to `local.test` domain.
- Do not modify the Dockerfile without updating `entrypoint.sh` accordingly.
- Do not change LMTP delivery target without verifying Dovecot's LMTP listener.

## Done criteria
- Postfix starts without errors.
- SMTP accepts mail on ports 1025/587.
- Mail is delivered to Dovecot via LMTP and appears in the user's Maildir.
