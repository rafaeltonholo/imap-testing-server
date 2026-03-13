# Dovecot Docker Project Guide

This file provides guidance for AI agents working with code in this repository.

## Repository Overview

This is a local IMAP/JMAP/SMTP test environment containing:

- Dovecot IMAP server with Maildir storage and OAuth2 support
- Stalwart JMAP server with built-in OAuth2 and admin API
- Postfix SMTP server for mail submission and delivery to Dovecot via LMTP
- Mock OAuth2 authorization server for token introspection
- Python automation scripts for user management, mail injection, and environment reset

## Common Commands

```bash
# First-time setup
python3 scripts/setup.py

# Start/stop
docker-compose up -d
docker-compose down

# Create user and seed inbox
python3 scripts/create_and_feed_account.py --email dev@local.test

# Inject mail
python3 scripts/send_message.py --email dev@local.test --message mails/16-test.eml

# Reset environment
python3 scripts/reset.py

# View logs
docker compose logs -f dovecot
```

## Common Pitfalls

- Do not commit SSL certificates (`ssl/` is gitignored); run `scripts/setup.py` to generate them.
- Do not inject mail too quickly without delay — Dovecot Maildir locks cause conflicts (default 2.5s delay).
- Do not modify `vmail/` or `stalwart-data/` directly; use scripts or `doveadm` commands.
- Do not hardcode container names in scripts; use the constants in `scripts/lib.py`.
- Do not add external Python dependencies; all scripts use stdlib only.
- Config files under `config/` are mounted read-only into Dovecot — changes require container restart.

## Areas

**BEFORE modifying or investigating, identify the area and read its docs.**

| Area                  | Location                   | Docs                                          |
|-----------------------|----------------------------|-----------------------------------------------|
| Docker Compose        | `docker-compose.yml`       | [SKILL.md](.ai/skills/docker-compose/SKILL.md)|
| Dovecot IMAP config   | `config/`                  | [SKILL.md](.ai/skills/dovecot/SKILL.md)       |
| Stalwart JMAP config  | `stalwart/`                | [SKILL.md](.ai/skills/stalwart/SKILL.md)      |
| Postfix SMTP config   | `postfix/`                 | [SKILL.md](.ai/skills/postfix/SKILL.md)       |
| OAuth2 mock server    | `oauth2-mock/`             | [SKILL.md](.ai/skills/oauth2/SKILL.md)        |
| Python scripts        | `scripts/`                 | [SKILL.md](.ai/skills/python-scripts/SKILL.md)|
| Email test data       | `mails/`                   | [SKILL.md](.ai/skills/email-testing/SKILL.md) |

## Running Validation

```bash
docker-compose config --quiet   # validate compose file
docker-compose up -d            # start services
docker compose logs dovecot     # check for startup errors
python3 scripts/create_and_feed_account.py --email dev@local.test  # end-to-end test
```

If Docker is not available, state it explicitly.
