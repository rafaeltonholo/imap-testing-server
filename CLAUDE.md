# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A local IMAP test environment using Dovecot and MailHog via Docker Compose. Intended only for development and testing — not production use.

## Common Commands

**First-time setup (generate SSL cert):**
```sh
./scripts/setup.sh
```

**Start/stop the environment:**
```sh
docker-compose up -d
docker-compose down
```

**View Dovecot logs:**
```sh
docker compose logs dovecot
docker compose logs -f dovecot   # follow
```

**Create a user and seed their inbox with all .eml files in mails/:**
```sh
./scripts/create_and_feed_account.sh --email dev@local.test
./scripts/create_and_feed_account.sh --email dev@local.test --password mypass --no-feed
./scripts/create_and_feed_account.sh --email dev@local.test --only-feed
```

**Inject a specific .eml file into a mailbox:**
```sh
./scripts/send_message.sh --email dev@local.test --message mails/16-test.eml
./scripts/send_message.sh --email dev@local.test --message mails/foo.eml --folder INBOX.Sent
```

**Generate and inject random test emails:**
```sh
./scripts/generate_random_emails.sh 50 dev@local.test        # 50 emails, 2.5s delay
./scripts/generate_random_emails.sh 50 dev@local.test 0      # no delay (may cause lock conflicts)
./scripts/generate_random_emails.sh                           # 100 emails to dev@local.test
```

**Generate a random email thread (saved to mails/threads/<name>/):**
```sh
python3 scripts/generate_thread.py --name onboarding --count 8 \
  --from "Alice <alice@local.test>" --from "Bob <bob@local.test>" \
  --to carol@local.test --cc dave@local.test

python3 scripts/generate_thread.py --name deploy-issue --count 12 \
  --from alice@local.test --from bob@local.test --from carol@local.test \
  --to dev-team@local.test --subject "Deployment rollback discussion"
```

**Send a pre-built thread into a mailbox:**
```sh
./scripts/send_thread.sh --thread api-v2-migration --email dev@local.test
./scripts/send_thread.sh --thread api-v2-migration --email dev@local.test --date now --delay 1
./scripts/send_thread.sh --thread onboarding --email dev@local.test --date "2026-03-01 10:00:00"
```

**Create a mailbox folder:**
```sh
./scripts/create_folder.sh --email dev@local.test --folder INBOX.Archive
```

**Reset the environment to a clean state:**
```sh
./scripts/reset.sh   # wipes vmail/ and restores default config/users
```

**Inspect mail inside the container:**
```sh
docker exec -it dovecot-dev doveadm fetch -u dev@local.test 'hdr.subject' mailbox INBOX
```

## Architecture

### Services (docker-compose.yml)
- **dovecot** (`dovecot/dovecot:latest`, container: `dovecot-dev`) — IMAP server
  - IMAP STARTTLS: `localhost:143`
  - IMAPS: `localhost:993`
  - Mail stored in `./vmail/` (mounted at `/srv/vmail`)
  - Config from `./config/` (mounted read-only at `/etc/dovecot/conf.d`)
  - Healthcheck via `doveadm who` (ready after ~15s start period)
- **mailhog** (`mailhog/mailhog:latest`, container: `mailhog-dev`) — SMTP capture
  - SMTP: `localhost:1025`
  - Web UI: `http://localhost:8025`

### User Management
- Users defined in `config/users` using `email:{PLAIN}password` format (passwd-file style)
- All users share UID/GID 1000 and have home at `/srv/vmail/<email>`
- Maildir layout: `./vmail/<email>/Maildir/`
- `create_and_feed_account.sh` manages adding/updating users in `config/users` and creating the Maildir on disk

### Scripts
All scripts share `scripts/lib.sh` which provides:
- `inject_mail EMAIL FILE_PATH [MAILBOX] [DELAY_SECS]` — copies a file into the container and saves it via `doveadm save`

The `INJECTION_DELAY` (default 2.5s) between successive injections prevents Dovecot file-lock conflicts when bulk-loading mail.

### Dovecot Configuration (`config/`)
- `10-auth.conf` — passwd-file auth using `config/users`; cleartext allowed for local dev
- `10-mail.conf` — Maildir storage under `/srv/vmail/%{user}/Maildir`
- `10-ssl.conf` — TLS using certs from `./ssl/`
- `10-logging.conf` — verbose logging to stdout (visible via `docker compose logs`)
- `15-namespace.conf` — IMAP namespace with `INBOX.` prefix and `.` separator

### SSL Certificates
Self-signed certs live in `ssl/` (gitignored). Run `./scripts/setup.sh` to generate them on a fresh clone.
