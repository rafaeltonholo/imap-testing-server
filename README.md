# Dovecot Docker IMAP Test Environment

This project provides a ready-to-use local IMAP and SMTP test environment using [Dovecot](https://www.dovecot.org/)
and [Postfix](https://www.postfix.org/) via Docker Compose. It is designed for testing email
clients, automation, and development workflows.

> [!IMPORTANT]
> DO NOT USE THIS PROJECT IN PRODUCTION. THIS IS A TEST ONLY PROJECT.

## Features

- **Dovecot IMAP server** (with STARTTLS and IMAPS)
- **Postfix SMTP server** with SASL authentication via Dovecot
- Preconfigured test users and sample `.eml` messages
- Scripts for creating users, feeding mail, and generating random test emails
- Easy log access and debugging

## Project Structure

- `docker-compose.yml` — Docker Compose setup for Dovecot and Postfix
- `config/` — Dovecot configuration files and user database
- `postfix/` — Postfix configuration and Dockerfile
- `mails/` — Sample `.eml` messages for injection
- `scripts/` — Helper scripts for user/mail management
- `vmail/` — Mail storage (mounted into the container)
- `ssl/` — SSL certificates for IMAPS (if needed)
- `logs/` — Dovecot logs

## Getting Started

### 1. Build and Start the Services

```sh
docker-compose up -d
```

### 2. Connection Details

| Service          | Address          | Port   | Notes                        |
|------------------|------------------|--------|------------------------------|
| IMAP (STARTTLS)  | `localhost`      | `143`  | Use STARTTLS for encryption  |
| IMAPS (TLS)      | `localhost`      | `993`  | Direct TLS connection        |
| SMTP             | `localhost`      | `1025` | For sending mail (no auth required from local networks) |
| SMTP Submission  | `localhost`      | `587`  | Authenticated sending (SASL) |

#### Connecting an IMAP Client (Thunderbird, Outlook, K-9 Mail, etc.)

**Incoming Mail (IMAP):**
- Server: `localhost`
- Port: `143` (STARTTLS) or `993` (SSL/TLS)
- Username: `dev@local.test`
- Password: `secret`
- Security: STARTTLS (port 143) or SSL/TLS (port 993)

**Outgoing Mail (SMTP):**
- Server: `localhost`
- Port: `587` (submission with SASL auth) or `1025` (open relay for local networks)
- Username: `dev@local.test` (required on port 587)
- Password: `secret` (required on port 587)
- Security: None (TLS is disabled for local dev simplicity)

### 3. Test Accounts

Default users are defined in [`config/users`](config/users):

| Email | Password |
|-------|----------|
| `dev@local.test` | `secret` |
| `dev1@local.test` | `secret` |
| `dev2@local.test` | `secret` |
| `dev3@local.test` | `secret` |
| `dev4@local.test` | `secret` |
| `dev5@local.test` | `secret` |
| `a_very_long-email_for_testing@local.test` | `secret` |

### 4. Injecting Test Emails

To feed sample emails into a test account:

```sh
./scripts/create_and_feed_account.sh --email dev@local.test
```

This will:

- Ensure the user exists in [`config/users`](config/users)
- Feed all `.eml` files from [`mails/`](mails/) into the user's INBOX

### 5. Generating Random Test Emails

Generate and inject random emails:

```sh
./scripts/generate_random_emails.sh 50 dev@local.test
```

### 6. Logs

Dovecot logs are available in the `logs/` directory and via:

```sh
docker compose logs dovecot
docker compose logs postfix
```

## Customization

- Add or edit users in [`config/users`](config/users)
- Place additional `.eml` files in [`mails/`](mails/) for injection
- Adjust Dovecot settings in [`config/`](config/)
- Adjust Postfix settings in [`postfix/main.cf`](postfix/main.cf)

## License

This project is for development and testing purposes only.

---

**Tip:** For advanced usage, see the helper scripts in [`scripts/`](scripts/).
