# Architecture Notes

## Principles

- Local-only development environment — not for production
- Convention over configuration for scripts
- Zero external Python dependencies (stdlib only)
- Shared utility layer in `scripts/lib.py`

## Service Topology

```
Client (IMAP/JMAP)
    │
    ├── Dovecot (IMAP, ports 143/993)
    │       ├── Maildir storage (./vmail/)
    │       ├── passwd-file auth (config/users)
    │       └── OAuth2 token introspection → oauth2-mock
    │
    ├── Stalwart (JMAP, port 8443)
    │       ├── SQLite storage (./stalwart-data/)
    │       ├── Built-in OAuth2 server
    │       └── Admin API (user provisioning)
    │
    ├── Postfix (SMTP, ports 1025/587)
    │       └── LMTP delivery → Dovecot
    │
    └── oauth2-mock (port 8080)
            └── Token introspection for Dovecot
```

## Data Flow

- Users defined in `config/users` (Dovecot) and synced to Stalwart via `sync_stalwart_users.py`
- Mail injected via `doveadm save` (scripts) or SMTP submission (Postfix → LMTP → Dovecot)
- Maildir layout: `./vmail/<email>/Maildir/`

## Dependency Direction

- Dovecot depends on oauth2-mock (for token introspection)
- Postfix depends on Dovecot (LMTP delivery)
- Stalwart is independent (own user store, own OAuth2)
- Scripts depend on Docker CLI (`docker exec`, `docker cp`)
