# Service Map

`docker-compose.yml` defines service names but no fixed `container_name` values;
Compose generates project-scoped container names.

## Published Ports

| Service | Selection | Host → container | Protocol |
|---------|-----------|------------------|----------|
| `dovecot` | Default | `127.0.0.1:1143` → `31143` | IMAP STARTTLS |
| `dovecot` | Default | `127.0.0.1:1993` → `31993` | IMAPS |
| `dovecot` | Default | `127.0.0.1:1110` → `31110` | POP3 STARTTLS |
| `dovecot` | Default | `127.0.0.1:1995` → `31990` | POP3S |
| `dovecot-operator` | Explicit profile only | `127.0.0.1:2993` → `31993` | Operator-only IMAPS |
| `postfix` | Default | `127.0.0.1:1025` → `25` | SMTP |
| `postfix` | Default | `127.0.0.1:1465` → `465` | SMTPS |
| `postfix` | Default | `127.0.0.1:1587` → `587` | SMTP submission |
| `oauth2-mock` | Default | `127.0.0.1:8080` → `8080` | OAuth2 mock HTTP |
| `stalwart` | Default | `0.0.0.0:8443` → `8443` | JMAP HTTP |

`dovecot-operator` is absent from the default resolved model. Select it only
with the explicit `dovecot-operator` profile.

## Networks

- Default services use the project default bridge.
- `dovecot-operator` is the only service attached to `operator-ingress`.
- `operator-ingress` is a dedicated non-internal bridge. Its operator port is
  still published only on host loopback.

## Dependency Chain

```text
oauth2-mock
├── dovecot (requires oauth2-mock healthy)
└── postfix (requires oauth2-mock and dovecot healthy)

dovecot-operator (profile-selected, no Compose dependency)
stalwart         (independent)
```

## Healthchecks

| Service | Method | Interval | Timeout | Start period |
|---------|--------|----------|---------|--------------|
| `dovecot` | `doveadm who` | 10s | 5s | 15s |
| `dovecot-operator` | Quiet POSIX checks for healthy `auth` and `imap-login` service status plus passive `/proc/net/tcp` LISTEN state for port 31993 | 5s | 3s | 10s |
| `oauth2-mock` | HTTP `/health` plus an internal socketmap `NOTFOUND` query on port 10001 | 5s | 3s | 5s |
| `stalwart` | Bash TCP open on container port 8443 | 10s | 5s | 15s |
| `postfix` | No healthcheck defined | — | — | — |
