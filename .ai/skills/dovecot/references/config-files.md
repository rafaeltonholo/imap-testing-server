# Dovecot Configuration Files

## Ordinary Service

The ordinary `dovecot` service mounts `config/` read-only at
`/etc/dovecot/conf.d/`.

| Repository file | Purpose |
|-----------------|---------|
| `10-auth.conf` | Ordinary passwd-file and OAuth2 passdbs plus eligibility-backed userdb |
| `10-logging.conf` | Verbose stdout logging with password redaction |
| `10-mail.conf` | Maildir storage below `/srv/vmail/%{user}` |
| `10-ssl.conf` | TLS certificate and private-key paths |
| `15-namespace.conf` | Private `INBOX.` namespace and special-use mailboxes |
| `20-auth-inet.conf` | Internal auth listener on container port 12345 |
| `20-doveadm.conf` | Disables the Dovecot HTTP listener |
| `20-lmtp.conf` | Internal LMTP listener on container port 24 |
| `20-pop3.conf` | Enables IMAP, POP3, and LMTP and pins POP3 behavior |

`users.seed` is tracked, non-secret address inventory used to seed the runtime
authority. It is not a Dovecot passwd file and is not loaded directly by
Dovecot.

## Operator Service

`operator/dovecot.conf` is a complete standalone configuration mounted
read-only at `/etc/dovecot/dovecot.conf` by the profile-selected
`dovecot-operator` service. It enables only TLS IMAP on container port 31993,
loads a hash-only master credential, checks targets against the shared runtime
eligibility authority, and denies direct ordinary-password login.
`operator/healthcheck.sh` is mounted read-only at
`/usr/local/bin/operator-healthcheck`; it uses POSIX shell built-ins plus
`doveadm` and fails closed on malformed or duplicate service/listener data.

## Generated Runtime Authorities

| Host path | Container path | Purpose |
|-----------|----------------|---------|
| `debug-dashboard/.runtime/dovecot/users` | `/etc/dovecot/runtime/users` | Canonical address plus validated Argon2id provider hash; ordinary passdb/userdb and operator target authority |
| `debug-dashboard/.runtime/dovecot-operator/master-users` | `/etc/dovecot/operator-auth/master-users` | Active protected master identity plus validated provider hash |

The canonical ordinary-user record is `<address>:<provider-hash>::::::`: eight
passwd-file columns (`user`, `password`, `uid`, `gid`, `gecos`, `home`, `shell`,
and `extra_fields`). The six post-password fields are empty because Dovecot
configuration supplies the UID, GID, and home defaults; their delimiters are
still required so passwd-file userdb recognizes the record.

Both runtime directories are mounted read-only. Writers use locked atomic
replacement on the host. Raw operator secrets live in a separate unmounted
runtime directory.

All ordinary users resolve to UID/GID 1000 with home
`/srv/vmail/<canonical-address>`.
