# Dovecot Authentication

## Mechanisms

Two authentication backends are configured:

### 1. Passwd-file (password auth)
- File: `config/users`
- Format: `email:{PLAIN}password`
- Cleartext passwords allowed (dev-only)
- Looked up via `passdb` and `userdb` in `10-auth.conf`

### 2. OAuth2 (token introspection)
- Dovecot validates Bearer tokens via HTTP introspection
- Introspection endpoint: `http://oauth2-mock:8080/introspect`
- Token format convention: `valid-<user>` returns active, `expired-<user>` returns inactive
- Configured in `10-auth.conf` passdb section

## Auth Flow

1. Client connects via IMAP (port 143 or 993)
2. Client authenticates with PLAIN (password) or OAUTHBEARER (token)
3. Dovecot checks passwd-file first, then falls back to OAuth2 introspection
4. On success, user home is resolved to `/srv/vmail/<email>`
