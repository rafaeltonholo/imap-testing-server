# Dovecot Docker IMAP/JMAP Test Environment

This project provides a ready-to-use local IMAP, JMAP, and SMTP test environment using [Dovecot](https://www.dovecot.org/),
[Stalwart](https://stalw.art/), and [Postfix](https://www.postfix.org/) via Docker Compose. It is designed for testing email
clients, automation, and development workflows.

> [!IMPORTANT]
> DO NOT USE THIS PROJECT IN PRODUCTION. THIS IS A TEST ONLY PROJECT.

## Features

- **Dovecot IMAP server** (with STARTTLS and IMAPS)
- **Stalwart JMAP server** with built-in OAuth2 and web admin
- **Postfix SMTP server** with SASL authentication via Dovecot
- **OAuth2 mock server** with full authorization code flow, token refresh, and error simulation
- Supports **PLAIN**, **LOGIN**, **OAUTHBEARER**, and **XOAUTH2** authentication on both IMAP and SMTP
- Preconfigured test users and sample `.eml` messages
- Scripts for creating users, feeding mail, and generating random test emails
- Easy log access and debugging

## Project Structure

- `docker-compose.yml` — Docker Compose setup for all services
- `config/` — Dovecot configuration files and user database
- `postfix/` — Postfix configuration and Dockerfile
- `stalwart/` — Stalwart JMAP server configuration
- `oauth2-mock/` — Mock OAuth2 authorization server
- `mails/` — Sample `.eml` messages for injection
- `scripts/` — Helper scripts for user/mail management
- `vmail/` — Dovecot mail storage (mounted into the container)
- `stalwart-data/` — Stalwart data (gitignored, created on first run)
- `ssl/` — SSL certificates for IMAPS (gitignored, generated via `scripts/setup.py`)
- `logs/` — Dovecot logs

## Getting Started

### 1. First-Time Setup

Generate SSL certificates (required once after cloning):

```sh
python3 scripts/setup.py
```

### 2. Start the Services

```sh
docker-compose up -d
```

This starts four services:

| Service     | Container      | Purpose                              |
| ----------- | -------------- | ------------------------------------ |
| Dovecot     | `dovecot-dev`  | IMAP server                          |
| Postfix     | `postfix-dev`  | SMTP server                          |
| Stalwart    | `stalwart-dev` | JMAP server (with built-in OAuth2)   |
| OAuth2 Mock | `oauth2-mock`  | OAuth2 server (for IMAP/SMTP OAuth2) |

### 3. Connection Details

| Service         | Address     | Port   | Notes                                             |
| --------------- | ----------- | ------ | ------------------------------------------------- |
| IMAP (STARTTLS) | `localhost` | `143`  | Use STARTTLS for encryption                       |
| IMAPS (TLS)     | `localhost` | `993`  | Direct TLS connection                             |
| SMTP            | `localhost` | `1025` | No auth required from local networks              |
| SMTP Submission | `localhost` | `587`  | Authenticated sending (SASL)                      |
| JMAP HTTP       | `localhost` | `8443` | JMAP protocol + web admin                         |
| OAuth2 Server   | `localhost` | `8080` | Authorization, token, and introspection endpoints |

### 4. Test Accounts

Default users are defined in [`config/users`](config/users):

| Email                                      | Password |
| ------------------------------------------ | -------- |
| `dev@local.test`                           | `secret` |
| `dev1@local.test`                          | `secret` |
| `dev2@local.test`                          | `secret` |
| `dev3@local.test`                          | `secret` |
| `dev4@local.test`                          | `secret` |
| `dev5@local.test`                          | `secret` |
| `a_very_long-email_for_testing@local.test` | `secret` |

## Authentication

Both IMAP and SMTP support two authentication methods: password-based (PLAIN/LOGIN) and OAuth2 (OAUTHBEARER/XOAUTH2).

### Password Authentication

#### IMAP (Python)

```python
import imaplib

imap = imaplib.IMAP4_SSL("localhost", 993)
imap.login("dev@local.test", "secret")
imap.select("INBOX")
typ, data = imap.search(None, "ALL")
print(f"Messages: {data[0].split()}")
imap.logout()
```

#### SMTP (Python)

```python
import smtplib
from email.message import EmailMessage

smtp = smtplib.SMTP("localhost", 587)
smtp.ehlo()
smtp.login("dev@local.test", "secret")

msg = EmailMessage()
msg["From"] = "dev@local.test"
msg["To"] = "dev2@local.test"
msg["Subject"] = "Test"
msg.set_content("Hello from SMTP!")
smtp.send_message(msg)
smtp.quit()
```

Port 1025 (SMTP) does not require authentication from local/Docker networks.

### OAuth2 Authentication

The OAuth2 mock server supports the full authorization code flow. You can either go through the complete flow or use tokens directly for quick testing.

#### OAuth2 Configuration for Email Clients

Any email client or app that supports custom OAuth2 providers needs the following configuration to authenticate against this environment:

| Parameter         | Value                                                       |
| ----------------- | ----------------------------------------------------------- |
| Authorization URL | `http://<host>:8080/authorize`                              |
| Token URL         | `http://<host>:8080/token`                                  |
| Scopes            | `imap smtp`                                                 |
| Client ID         | any value (e.g. `myapp`)                                    |
| Client Secret     | any value (e.g. `mysecret`)                                 |
| Redirect URI      | depends on the client (see below)                           |
| Discovery URL     | `http://<host>:8080/.well-known/oauth-authorization-server` |

Replace `<host>` with `localhost` when the client runs on the same machine, or with your machine's LAN IP (e.g. `192.168.1.50`) when connecting from a phone or another device.

> The mock accepts **any** `client_id` and `client_secret` values — no registration needed.

**Scopes:**

| Scope       | Grants access to         |
| ----------- | ------------------------ |
| `imap`      | IMAP authentication only |
| `smtp`      | SMTP authentication only |
| `imap smtp` | Both IMAP and SMTP       |

#### Thunderbird for Android

Thunderbird for Android ships with hardcoded OAuth2 configurations for known providers (Google, Microsoft) and does **not** expose a UI to add custom OAuth2 endpoints. To use OAuth2 with this mock, you need to inject a custom provider configuration.

**Step 1 — Find your machine's LAN IP:**

```sh
# macOS
ipconfig getifaddr en0

# Linux
hostname -I | awk '{print $1}'
```

The phone and your machine must be on the same network. We'll refer to this IP as `<host>` below.

**Step 2 — Add a custom OAuth2 provider in Thunderbird's config:**

Thunderbird for Android stores its provider list internally. Since there is no settings UI for custom providers, you have two options:

- **Option A: Use password authentication instead.** Configure the account with PLAIN/LOGIN auth — this works out of the box with the same server settings and the [test account](#4-test-accounts) credentials.

- **Option B: Build a patched version** of Thunderbird for Android that includes your custom provider in its OAuth2 registry, using these values:

  ```plaintext
  hostname:         local.test
  authorization_url: http://<host>:8080/authorize
  token_url:        http://<host>:8080/token
  client_id:        thunderbird-android
  client_secret:    (empty or any value)
  redirect_uri:     (as defined by the app's OAuth2 callback handler)
  scopes:           imap smtp
  ```

**Step 3 — Configure the account in Thunderbird:**

| Setting       | Value            |
| ------------- | ---------------- |
| Email         | `dev@local.test` |
| IMAP server   | `<host>`         |
| IMAP port     | `993`            |
| IMAP security | SSL/TLS          |
| IMAP auth     | OAuth2           |
| SMTP server   | `<host>`         |
| SMTP port     | `587`            |
| SMTP security | None             |
| SMTP auth     | OAuth2           |

When prompted, Thunderbird opens the authorization URL in a browser. The mock consent page lets you pick the email address and click **Authorize**. The token is returned to the app automatically.

> **Note:** Most mobile email clients (Gmail app, Apple Mail, Outlook) have the same limitation — they only support OAuth2 for their own hardcoded provider list. The programmatic examples below (Python, curl, command line) are the most practical way to test the full OAuth2 flow against the mock.

#### OAuth2 Endpoints

| Endpoint                                  | Method | Purpose                                              |
| ----------------------------------------- | ------ | ---------------------------------------------------- |
| `/.well-known/oauth-authorization-server` | GET    | Discovery document                                   |
| `/authorize`                              | GET    | Shows consent page                                   |
| `/authorize`                              | POST   | Processes consent, redirects with auth code          |
| `/token`                                  | POST   | Exchange auth code or refresh token for access token |
| `/introspect`                             | POST   | Validate an access token (RFC 7662)                  |
| `/health`                                 | GET    | Healthcheck                                          |

#### Option A: Full OAuth2 Authorization Code Flow

This is the standard flow an application would use.

**Step 1 — Redirect user to authorize:**

```sh
http://localhost:8080/authorize?client_id=myapp&redirect_uri=http://localhost:3000/callback&response_type=code&scope=imap+smtp&state=random123
```

The user sees a consent page where they pick an email address and click "Authorize" (or "Deny").

**Step 2 — Receive auth code via redirect:**

The mock redirects to your `redirect_uri` with an authorization code:

```sh
http://localhost:3000/callback?code=authcode-abc123...&state=random123
```

**Step 3 — Exchange auth code for tokens:**

```sh
curl -X POST http://localhost:8080/token \
  -d "grant_type=authorization_code" \
  -d "code=authcode-abc123..." \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "client_id=myapp" \
  -d "client_secret=mysecret"
```

Response:

```json
{
  "access_token": "valid-dev@local.test",
  "token_type": "bearer",
  "expires_in": 3600,
  "refresh_token": "refresh-dev@local.test-...",
  "scope": "imap smtp"
}
```

**Step 4 — Use access token for IMAP/SMTP** (see examples below).

**Step 5 — Refresh when expired:**

```sh
curl -X POST http://localhost:8080/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=refresh-dev@local.test-..." \
  -d "client_id=myapp"
```

> Any `client_id` and `client_secret` values are accepted by the mock.

#### Option B: Direct Token Convention (Quick Testing)

For quick testing without going through the browser flow, you can construct tokens directly using these prefixes:

| Token                    | Result                                       |
| ------------------------ | -------------------------------------------- |
| `valid-dev@local.test`   | Authentication succeeds for `dev@local.test` |
| `expired-dev@local.test` | Token expired error                          |
| `scope-dev@local.test`   | Insufficient scope error                     |
| `anything-else`          | Invalid token error                          |

These tokens work with both IMAP/SMTP authentication and the `/introspect` endpoint.

#### IMAP with OAuth2 (Python)

```python
import imaplib

user = "dev@local.test"
access_token = "valid-dev@local.test"  # from /token endpoint or direct convention

# Build XOAUTH2 string
auth_string = f"user={user}\x01auth=Bearer {access_token}\x01\x01"

imap = imaplib.IMAP4_SSL("localhost", 993)
imap.authenticate("XOAUTH2", lambda x: auth_string.encode())
imap.select("INBOX")
typ, data = imap.search(None, "ALL")
print(f"Messages: {data[0].split()}")
imap.logout()
```

#### SMTP with OAuth2 (Python)

```python
import smtplib
import base64
from email.message import EmailMessage

user = "dev@local.test"
access_token = "valid-dev@local.test"  # from /token endpoint or direct convention

# Build XOAUTH2 string
auth_string = f"user={user}\x01auth=Bearer {access_token}\x01\x01"
auth_b64 = base64.b64encode(auth_string.encode()).decode()

smtp = smtplib.SMTP("localhost", 587)
smtp.ehlo()
code, resp = smtp.docmd("AUTH", f"XOAUTH2 {auth_b64}")
print(f"Auth: {code} {resp}")  # 235 = success

msg = EmailMessage()
msg["From"] = user
msg["To"] = "dev2@local.test"
msg["Subject"] = "Test via OAuth2"
msg.set_content("Authenticated with XOAUTH2!")
smtp.send_message(msg)
smtp.quit()
```

#### IMAP with OAuth2 (Command Line)

```sh
# Build base64-encoded XOAUTH2 token
TOKEN=$(printf 'user=dev@local.test\x01auth=Bearer valid-dev@local.test\x01\x01' | base64)

# Connect and authenticate
echo -e "A01 AUTHENTICATE XOAUTH2 $TOKEN\nA02 LIST \"\" *\nA03 LOGOUT" \
  | openssl s_client -connect localhost:993 -quiet 2>/dev/null
```

#### Full OAuth2 Flow (Command Line)

```sh
# 1. Open authorize URL in browser
open "http://localhost:8080/authorize?client_id=myapp&redirect_uri=http://localhost:3000/callback&response_type=code&scope=imap+smtp&state=xyz"

# 2. After approving, copy the code from the redirect URL, then exchange it:
curl -s -X POST http://localhost:8080/token \
  -d "grant_type=authorization_code&code=YOUR_CODE&redirect_uri=http://localhost:3000/callback&client_id=myapp" \
  | python3 -m json.tool

# 3. Use the returned access_token for IMAP/SMTP as shown above

# 4. Refresh when needed:
curl -s -X POST http://localhost:8080/token \
  -d "grant_type=refresh_token&refresh_token=YOUR_REFRESH_TOKEN&client_id=myapp" \
  | python3 -m json.tool
```

### Simulating Authentication Errors

The mock supports several error simulation mechanisms:

#### Token-based errors

Use the token prefix conventions with either direct IMAP/SMTP auth or the `/introspect` endpoint:

```sh
# Expired token
curl -X POST http://localhost:8080/introspect -d "token=expired-dev@local.test"
# → {"active": false, "error": "expired_token", ...}

# Insufficient scope
curl -X POST http://localhost:8080/introspect -d "token=scope-dev@local.test"
# → {"active": false, "error": "insufficient_scope", ...}

# Invalid token
curl -X POST http://localhost:8080/introspect -d "token=garbage"
# → {"active": false, "error": "invalid_token", ...}
```

#### Forced HTTP errors

Append `?status=<code>` to any endpoint to force an HTTP error response:

```sh
# Simulate server outage on token exchange
curl -X POST "http://localhost:8080/token?status=500" \
  -d "grant_type=authorization_code&code=test"
# → HTTP 500, {"error": "simulated_server_error"}

# Simulate timeout on introspection
curl -X POST "http://localhost:8080/introspect?status=503" -d "token=valid-dev@local.test"
# → HTTP 503, {"error": "simulated_server_error"}
```

#### Simulated latency

Append `?delay=<seconds>` to any endpoint to add latency:

```sh
# 3-second delay on token exchange
curl -X POST "http://localhost:8080/token?delay=3" \
  -d "grant_type=refresh_token&refresh_token=..."
```

#### OAuth2 flow errors

```sh
# User denies consent → redirect includes error=access_denied

# Reuse an auth code → {"error": "invalid_grant", "error_description": "Authorization code is invalid or already used"}

# Expired auth code (after 60s) → {"error": "invalid_grant", "error_description": "Authorization code has expired"}

# Wrong redirect_uri → {"error": "invalid_grant", "error_description": "redirect_uri does not match"}

# Invalid refresh token → {"error": "invalid_grant", "error_description": "Refresh token is invalid or revoked"}

# Unknown grant type → {"error": "unsupported_grant_type"}
```

## JMAP (Stalwart)

[Stalwart](https://stalw.art/) provides a [JMAP](https://jmap.io/) server alongside the Dovecot IMAP setup. JMAP is a modern, JSON-based API for email access — an alternative to IMAP designed for web and mobile clients.

### Endpoints

| Endpoint           | URL                                                            |
| ------------------ | -------------------------------------------------------------- |
| JMAP Session       | `http://localhost:8443/.well-known/jmap`                       |
| JMAP API           | `http://localhost:8443/jmap`                                   |
| Web Admin          | `http://localhost:8443/` (login: `admin` / `secret`)           |
| OAuth2 Discovery   | `http://localhost:8443/.well-known/oauth-authorization-server` |
| OAuth2 Authorize   | `http://localhost:8443/authorize/code`                         |
| OAuth2 Device Flow | `POST http://localhost:8443/auth/device`                       |

### User Provisioning

Stalwart uses its own internal directory — users from `config/users` must be synced into it separately:

```sh
python3 scripts/sync_stalwart_users.py
```

Run this after the first `docker-compose up -d` or whenever you add new users to `config/users`. After syncing, Stalwart users share the same email/password credentials as Dovecot.

### Authentication

Stalwart supports two authentication methods:

**Basic auth** (same credentials as Dovecot):

```sh
# JMAP session resource
curl -u dev@local.test:secret http://localhost:8443/.well-known/jmap
```

**OAuth2 Bearer tokens** (via Stalwart's built-in OAuth2 server):

```sh
# 1. Start a device authorization flow
curl -X POST http://localhost:8443/auth/device -d "client_id=myapp"
# → returns verification_uri and device_code

# 2. Open verification_uri in browser, enter the user_code, approve access

# 3. Poll for the token
curl -X POST http://localhost:8443/auth/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "client_id=myapp" \
  -d "device_code=DEVICE_CODE_FROM_STEP_1"
# → returns access_token

# 4. Use the token
curl -H "Authorization: Bearer ACCESS_TOKEN" http://localhost:8443/jmap
```

> Stalwart's OAuth2 server is separate from the `oauth2-mock` service. The mock is used by Dovecot/Postfix for IMAP/SMTP OAuth2 authentication. Stalwart has its own built-in OAuth2 server backed by its internal user directory.

### JMAP Usage (Python)

```python
import json
import urllib.request

JMAP_URL = "http://localhost:8443/jmap"
CREDENTIALS = "dev@local.test:secret"

# Helper to make JMAP requests with Basic auth
import base64
auth = base64.b64encode(CREDENTIALS.encode()).decode()
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Basic {auth}",
}

# Get the JMAP session to find account ID
session_req = urllib.request.Request(
    "http://localhost:8443/.well-known/jmap", headers=headers
)
with urllib.request.urlopen(session_req) as resp:
    session = json.loads(resp.read())
account_id = session["primaryAccounts"]["urn:ietf:params:jmap:mail"]

# Query mailboxes
body = json.dumps({
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
        ["Mailbox/get", {"accountId": account_id}, "0"]
    ],
}).encode()

req = urllib.request.Request(JMAP_URL, data=body, headers=headers)
with urllib.request.urlopen(req) as resp:
    result = json.loads(resp.read())
    for mailbox in result["methodResponses"][0][1]["list"]:
        print(f"{mailbox['name']}: {mailbox.get('totalEmails', 0)} emails")
```

### JMAP Usage (curl)

```sh
# Get session (discover account ID)
curl -s -u dev@local.test:secret http://localhost:8443/.well-known/jmap | python3 -m json.tool

# Query mailboxes (replace ACCOUNT_ID with the value from the session)
curl -s -u dev@local.test:secret http://localhost:8443/jmap \
  -H "Content-Type: application/json" \
  -d '{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Mailbox/get", {"accountId": "ACCOUNT_ID"}, "0"]
    ]
  }' | python3 -m json.tool

# Search emails
curl -s -u dev@local.test:secret http://localhost:8443/jmap \
  -H "Content-Type: application/json" \
  -d '{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
      ["Email/query", {"accountId": "ACCOUNT_ID", "limit": 10}, "0"],
      ["Email/get", {
        "accountId": "ACCOUNT_ID",
        "#ids": {"resultOf": "0", "name": "Email/query", "path": "/ids"},
        "properties": ["subject", "from", "receivedAt"]
      }, "1"]
    ]
  }' | python3 -m json.tool
```

## Mail Management

### Create a User and Seed Their Inbox

```sh
python3 scripts/create_and_feed_account.py --email dev@local.test
python3 scripts/create_and_feed_account.py --email dev@local.test --password mypass --no-feed
python3 scripts/create_and_feed_account.py --email dev@local.test --only-feed
```

### Inject a Specific Email

```sh
python3 scripts/send_message.py --email dev@local.test --message mails/16-test.eml
python3 scripts/send_message.py --email dev@local.test --message mails/foo.eml --folder INBOX.Sent
```

### Generate and Inject Random Emails

```sh
python3 scripts/generate_random_emails.py 50 dev@local.test            # 50 emails, 2.5s delay
python3 scripts/generate_random_emails.py 50 dev@local.test --delay 0  # no delay
python3 scripts/generate_random_emails.py                               # 100 emails to dev@local.test
```

### Generate and Send Email Threads

```sh
# Generate a thread
python3 scripts/generate_thread.py --name onboarding --count 8 \
  --from "Alice <alice@local.test>" --from "Bob <bob@local.test>" \
  --to carol@local.test --cc dave@local.test

# Send a thread into a mailbox
python3 scripts/send_thread.py --thread onboarding --email dev@local.test
python3 scripts/send_thread.py --thread onboarding --email dev@local.test --date now --delay 1
```

### Create a Mailbox Folder

```sh
python3 scripts/create_folder.py --email dev@local.test --folder INBOX.Archive
```

### Sync Users into Stalwart

```sh
python3 scripts/sync_stalwart_users.py
```

### Reset the Environment

```sh
python3 scripts/reset.py   # wipes vmail/, stalwart-data/, and restores default config/users
```

### Inspect Mail Inside the Container

```sh
docker exec -it dovecot-dev doveadm fetch -u dev@local.test 'hdr.subject' mailbox INBOX
```

## Logs

```sh
docker compose logs dovecot       # Dovecot logs
docker compose logs postfix       # Postfix logs
docker compose logs stalwart      # Stalwart JMAP logs
docker compose logs oauth2-mock   # OAuth2 mock logs
docker compose logs -f dovecot    # Follow logs
```

Dovecot has verbose auth logging enabled (`auth_verbose = yes`, `mail_debug = yes`), which is useful for debugging authentication issues.

## Customization

- Add or edit users in [`config/users`](config/users)
- Place additional `.eml` files in [`mails/`](mails/) for injection
- Adjust Dovecot settings in [`config/`](config/)
- Adjust Postfix settings in [`postfix/main.cf`](postfix/main.cf)
- Adjust Stalwart settings in [`stalwart/config.toml`](stalwart/config.toml)
- Modify OAuth2 mock behavior in [`oauth2-mock/server.py`](oauth2-mock/server.py)

## License

This project is for development and testing purposes only.
