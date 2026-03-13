# Stalwart OAuth2

Stalwart has a built-in OAuth2 authorization server (separate from the mock oauth2-mock service).

## Endpoints

| Endpoint                                          | Method | Purpose               |
|---------------------------------------------------|--------|-----------------------|
| `/.well-known/oauth-authorization-server`         | GET    | Discovery metadata    |
| `/authorize/code`                                 | GET    | Browser authorization |
| `/auth/device`                                    | POST   | Device flow initiation|
| `/auth/token`                                     | POST   | Token exchange        |

## Usage

Stalwart OAuth2 is used for JMAP authentication. The device flow is useful for CLI testing:

```bash
# Initiate device flow
curl -X POST http://localhost:8443/auth/device -d 'client_id=test-client'
```

## Note

The `oauth2-mock` service is separate and used only by Dovecot for IMAP OAuth2 introspection.
Stalwart's built-in OAuth2 is for JMAP clients.
