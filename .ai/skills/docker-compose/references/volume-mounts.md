# Volume Mounts

## Ordinary Dovecot

| Host path | Container path | Mode | Purpose |
|-----------|----------------|------|---------|
| `./config` | `/etc/dovecot/conf.d` | ro | Ordinary Dovecot configuration |
| `./debug-dashboard/.runtime/dovecot` | `/etc/dovecot/runtime` | ro | Generated hashed eligibility/passwd authority |
| `./ssl` | `/etc/dovecot/ssl` | ro | TLS certificate and private key |
| `./vmail` | `/srv/vmail` | rw | Maildir storage |
| `./logs` | `/var/log/dovecot` | rw | Dovecot log storage |

## Operator Dovecot

The operator service exists only behind the explicit `dovecot-operator`
profile.

| Host path | Container path | Mode | Purpose |
|-----------|----------------|------|---------|
| `./config/operator/dovecot.conf` | `/etc/dovecot/dovecot.conf` | ro | Standalone IMAP-only operator configuration |
| `./config/operator/healthcheck.sh` | `/usr/local/bin/operator-healthcheck` | ro | POSIX operator service/listener healthcheck |
| `./debug-dashboard/.runtime/dovecot` | `/etc/dovecot/runtime` | ro | Shared generated target-eligibility authority |
| `./debug-dashboard/.runtime/dovecot-operator` | `/etc/dovecot/operator-auth` | ro | Security-owned directory containing the hash-only `master-users` input |
| `./ssl` | `/etc/dovecot/ssl` | ro | TLS certificate and private key |
| `./vmail` | `/srv/vmail` | rw | Shared Maildir storage |

The `/etc/dovecot/operator-auth` bind sets `create_host_path: false`; bootstrap
must create and validate its host directory before service selection. Raw
operator secret slots remain under
`./debug-dashboard/.runtime/secrets` and are not mounted into any container.

## OAuth2 Mock

| Host path | Container path | Mode | Purpose |
|-----------|----------------|------|---------|
| `./debug-dashboard/.runtime/dovecot` | `/etc/dovecot/runtime` | ro | Shared eligibility authority for OAuth and Postfix socketmap decisions |

## Postfix

| Host path | Container path | Mode | Purpose |
|-----------|----------------|------|---------|
| `./ssl` | `/etc/postfix/ssl` | ro | SMTP TLS certificate and private key |

## Stalwart

| Host path | Container path | Mode | Purpose |
|-----------|----------------|------|---------|
| `./stalwart/config.toml` | `/opt/stalwart/etc/config.toml` | ro | Stalwart configuration |
| `./stalwart-data` | `/opt/stalwart/data` | rw | Stalwart data |

## Notes

- Dovecot configuration and authority mounts are read-only.
- `vmail/`, `stalwart-data/`, `ssl/`, and `debug-dashboard/.runtime/` are
  runtime data rather than tracked credentials.
- Apply Dovecot configuration changes through the repository lifecycle; do not
  edit mounted files inside a container.
