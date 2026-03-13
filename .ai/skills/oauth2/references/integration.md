# OAuth2 Integration Map

## Dovecot → oauth2-mock

- Dovecot validates IMAP OAUTHBEARER tokens via introspection
- Endpoint: `http://oauth2-mock:8080/introspect` (container network)
- Configured in `config/10-auth.conf`
- Token is sent as POST body: `token=<bearer_token>`
- Dovecot expects `active: true` and `username` in response

## Stalwart (independent)

- Stalwart has its own built-in OAuth2 server
- Does NOT use oauth2-mock
- Separate user store and token management
- Used for JMAP client authentication

## Client Testing

```bash
# Test IMAP with OAuth2 token
openssl s_client -connect localhost:993 -quiet <<< $'A LOGIN dev@local.test valid-dev@local.test\nB LOGOUT'

# Or use curl for introspection directly
curl -X POST http://localhost:8080/introspect -d 'token=valid-dev@local.test'
```
