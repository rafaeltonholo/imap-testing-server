# Dovecot Configuration Files

All files live in `config/` and are mounted read-only at `/etc/dovecot/conf.d/`.

| File                | Purpose                                                        |
|---------------------|----------------------------------------------------------------|
| `10-auth.conf`      | Authentication: passwd-file backend + OAuth2 introspection     |
| `10-logging.conf`   | Verbose logging to stdout (for `docker compose logs`)          |
| `10-mail.conf`      | Maildir storage location under `/srv/vmail/%{user}/Maildir`    |
| `10-ssl.conf`       | TLS certificate paths (`/etc/dovecot/ssl/`)                    |
| `15-namespace.conf` | IMAP namespace with `INBOX.` prefix and `.` separator          |
| `20-auth-inet.conf` | Auth inet listener for SASL                                    |
| `20-lmtp.conf`      | LMTP service for receiving mail from Postfix                   |
| `users`             | Passwd-file with `email:{PLAIN}password` entries               |

## User Format

```
dev@local.test:{PLAIN}dev
another@local.test:{PLAIN}password
```

All users share UID/GID 1000 with home at `/srv/vmail/<email>`.
