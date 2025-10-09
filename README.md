# Dovecot Docker IMAP Test Environment

This project provides a ready-to-use local IMAP test environment using [Dovecot](https://www.dovecot.org/)
and [MailHog](https://github.com/mailhog/MailHog) via Docker Compose. It is designed for testing email
clients, automation, and development workflows.

> [!IMPORTANT]
> DO NOT USE THIS PROJECT IN PRODUCTION. THIS IS A TEST ONLY PROJECT.

## Features

- **Dovecot IMAP server** (with STARTTLS and IMAPS)
- **MailHog SMTP server** for capturing outgoing mail
- Preconfigured test users and sample `.eml` messages
- Scripts for creating users, feeding mail, and generating random test emails
- Easy log access and debugging

## Project Structure

- `docker-compose.yml` — Docker Compose setup for Dovecot and MailHog
- `config/` — Dovecot configuration files and user database
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

- IMAP (STARTTLS): `localhost:143`
- IMAPS (TLS): `localhost:993`
- SMTP (MailHog): `localhost:1025`
- MailHog Web UI: [http://localhost:8025](http://localhost:8025)

### 2. Test Accounts

Default users are defined in [`config/users`](config/users):

```plaintext
dev@local.test / secret3
dev1@local.test / secret3
dev2@local.test / secret3
dev3@local.test / secret3
dev4@local.test / secret3
```

### 3. Injecting Test Emails

To feed sample emails into a test account:

```sh
./scripts/create_and_feed_account.sh --email dev@local.test
```

This will:

- Ensure the user exists in [`config/users`](config/users)
- Feed all `.eml` files from [`mails/`](mails/) into the user's INBOX

### 4. Generating Random Test Emails

Generate and inject random emails:

```sh
./scripts/generate_random_emails.sh 50 dev@local.test
```

### 5. Accessing Mail

- Use any IMAP client (e.g., Thunderbird, Outlook, K-9 Mail) to connect to `localhost:143` or
  `localhost:993` with the credentials above.
- Outgoing mail sent via SMTP will appear in the MailHog web UI.

### 6. Logs

Dovecot logs are available in the `logs/` directory and via:

```sh
docker compose logs dovecot
```

## Customization

- Add or edit users in [`config/users`](config/users)
- Place additional `.eml` files in [`mails/`](mails/) for injection
- Adjust Dovecot settings in [`config/`](config/)

## License

This project is for development and testing purposes only.

---

**Tip:** For advanced usage, see the helper scripts in [`scripts/`](scripts/).
