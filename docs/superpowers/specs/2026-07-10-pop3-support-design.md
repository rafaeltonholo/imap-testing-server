# POP3 Support — Design Spec

**Date:** 2026-07-10
**Status:** Approved

## Goal

Enable POP3 access to the Dovecot mail store in the local dev/test environment, alongside existing IMAP and JMAP support.

## Scope

Dovecot only. Stalwart (JMAP) is out of scope.

## Changes

### 1. `config/20-pop3.conf` (new file)

Enables POP3 and configures its behavior:

```
protocols = imap pop3 lmtp

pop3_uidl_format = %{uid | hex(8)}%{uidvalidity | hex(8)}
pop3_no_flag_updates = no
```

- `protocols` adds `pop3` alongside the already-active `imap` and `lmtp`.
- `pop3_uidl_format = %{uid | hex(8)}%{uidvalidity | hex(8)}` — stable UIDL format derived from message UID/validity; ensures clients using "leave mail on server" see consistent IDs across sessions. (Dovecot 2.4 syntax; the older `%08Xu%08Xv` form fails to parse on the `dovecot:latest` 2.4.x image.)
- `pop3_no_flag_updates = no` — reading via POP3 marks messages `\Seen` in IMAP too, enabling cross-protocol state testing.

### 2. `docker-compose.yml` — Dovecot port mappings

Two new entries under the `dovecot` service `ports`:

```yaml
- "110:31110"   # POP3 STARTTLS
- "995:31990"   # POP3S (implicit TLS)
```

Follows the existing `+30000` offset pattern used by the Dovecot image (`31143`/`31993` for IMAP, `31110` for POP3). Note: the image's built-in `pop3s` listener uses port `31990` (not `31995`), so POP3S must map to `31990`.

### 3. Documentation

Update `CLAUDE.md` and `README.md` architecture sections to list:
- POP3 STARTTLS: `localhost:110`
- POP3S: `localhost:995`

## What Does Not Change

- Auth config (`10-auth.conf`) — passwd-file and OAuth2 passdb work for POP3 unchanged.
- Mail storage (`10-mail.conf`) — Maildir layout is protocol-agnostic.
- SSL config (`10-ssl.conf`) — existing certs cover POP3S.
- Scripts — all inject/feed scripts use `doveadm` directly and are protocol-agnostic.

## Testing

After applying changes:

```sh
docker-compose up -d
# POP3 STARTTLS
openssl s_client -starttls pop3 -connect localhost:110
# POP3S
openssl s_client -connect localhost:995
```

Both should complete the TLS handshake and show `+OK Dovecot ready`.
