# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A local IMAP test environment using Dovecot and MailHog via Docker Compose. Intended only for development and testing — not production use.

## Common Commands

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
./scripts/generate_random_emails.sh 50 dev@local.test   # 50 emails
./scripts/generate_random_emails.sh                      # 100 emails to dev@local.test
```

**Inspect mail inside the container:**
```sh
docker exec -it dovecot-dev doveadm fetch -u dev@local.test 'hdr.subject' mailbox INBOX
```

**Create a mailbox folder:**
```sh
./scripts/create_folder.sh "INBOX.MyFolder"   # creates for dev1@local.test (hardcoded)
```

## Architecture

### Services (docker-compose.yml)
- **dovecot** (`dovecot/dovecot:latest`, container: `dovecot-dev`) — IMAP server
  - IMAP STARTTLS: `localhost:143`
  - IMAPS: `localhost:993`
  - Mail stored in `./vmail/` (mounted at `/srv/vmail`)
  - Config from `./config/` (mounted read-only at `/etc/dovecot/conf.d`)
- **mailhog** (`mailhog/mailhog:latest`, container: `mailhog-dev`) — SMTP capture
  - SMTP: `localhost:1025`
  - Web UI: `http://localhost:8025`

### User Management
- Users defined in `config/users` using `email:{PLAIN}password` format (passwd-file style)
- All users share UID/GID 1000 and have home at `/srv/vmail/<email>`
- Maildir layout: `./vmail/<email>/Maildir/`
- The `create_and_feed_account.sh` script manages adding/updating users in `config/users` and creating the Maildir on disk

### Dovecot Configuration (`config/`)
- `10-auth.conf` — passwd-file auth using `config/users`; cleartext allowed for local dev
- `10-mail.conf` — Maildir storage under `/srv/vmail/%{user}/Maildir`
- `10-ssl.conf` — TLS using certs from `./ssl/`
- `10-logging.conf` — verbose logging to stdout (visible via `docker compose logs`)
- `15-namespace.conf` — IMAP namespace with `INBOX.` prefix and `.` separator

### Mail Injection
Scripts inject `.eml` files by copying them into the container's `/tmp/` then calling `doveadm save`. The `sleep 2.5` between injections prevents Dovecot file lock conflicts.

### SSL Certificates
Self-signed certs live in `ssl/` (gitignored). Regenerate with:
```sh
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/tls.key -out ssl/tls.crt -subj "/CN=localhost"
```
