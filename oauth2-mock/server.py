"""
Mock OAuth2 Authorization Server

Implements a full OAuth2 flow for local dev/testing of IMAP and SMTP clients.

Endpoints:
  GET  /.well-known/oauth-authorization-server  → discovery document
  GET  /authorize   → authorization page (shows consent form, issues auth code)
  POST /token       → exchange auth code or refresh token for access token
  POST /introspect  → validate an access token (RFC 7662)
  GET  /health      → healthcheck

Auth code flow:
  1. App redirects user to /authorize?client_id=...&redirect_uri=...&response_type=code&scope=...&state=...
  2. User sees consent page, picks a username, clicks Authorize
  3. Mock redirects to redirect_uri?code=<auth_code>&state=<state>
  4. App exchanges code at POST /token (grant_type=authorization_code)
  5. Mock returns access_token + refresh_token
  6. App uses access_token for IMAP/SMTP XOAUTH2 auth
  7. When token expires, app calls POST /token (grant_type=refresh_token)

Token conventions (still work for direct introspection testing):
  - "valid-<username>"       → active only while <username> is eligible
  - "expired-<username>"     → expired token error
  - "scope-<username>"       → insufficient_scope error
  - anything else            → invalid_token error

Query parameters (on any endpoint):
  - ?delay=<seconds>         → adds latency before responding
  - ?status=<code>           → forces an HTTP status code (e.g. 500)

Client credentials:
  - Any client_id / client_secret are accepted (it's a mock).

Token lifetimes:
  - Access tokens:  3600s (1 hour) by default
  - Refresh tokens: do not expire, but are revoked when eligibility is removed
  - Auth codes:     60s
"""

import base64
import binascii
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlencode, urlparse

PORT = 8080
BASE_URL = f"http://localhost:{PORT}"
ELIGIBILITY_FILE = Path("/etc/dovecot/runtime/users")

# In-memory stores
auth_codes = {}    # code → {username, redirect_uri, client_id, exp}
refresh_tokens = {}  # token → {username, client_id, scope}
access_tokens = {}   # token → {username, scope, exp}

ACCESS_TOKEN_TTL = 3600  # 1 hour
AUTH_CODE_TTL = 60        # 1 minute


class EligibilityReader:
    """Read the current Dovecot passwd-file authority without caching it."""

    MAX_FILE_BYTES = 1024 * 1024
    MAX_ADDRESS_LENGTH = 254
    MAX_LOCAL_PART_LENGTH = 64
    MAX_DOMAIN_LENGTH = 253
    MAX_HASH_LENGTH = 4 * 1024
    MAX_ENCODED_SEGMENT_LENGTH = 1024
    LOCAL_PART = re.compile(r"[a-z0-9](?:[a-z0-9._+%-]{0,62}[a-z0-9])?")
    DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
    ARGON2_HASH = re.compile(
        r"\{ARGON2ID\}"
        r"\$argon2id"
        r"\$v=19"
        r"\$m=([1-9][0-9]{0,9}),t=([1-9][0-9]{0,9}),p=([1-9][0-9]{0,9})"
        r"\$([A-Za-z0-9+/]{1,1024})"
        r"\$([A-Za-z0-9+/]{1,1024})"
    )

    def __init__(self, path=ELIGIBILITY_FILE):
        self._path = Path(path)

    def is_eligible(self, username):
        if not self._is_canonical_address(username):
            return False
        try:
            return username in self._read_addresses()
        except (OSError, UnicodeError, ValueError):
            return False

    def _read_addresses(self):
        self._require_nonsymlink_path()
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self._path, flags)
        try:
            before = os.fstat(descriptor)
            self._require_secure_regular_file(before)
            chunks = []
            remaining = self.MAX_FILE_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            contents = b"".join(chunks)
            if len(contents) > self.MAX_FILE_BYTES:
                raise ValueError("eligibility authority is too large")
            after = os.fstat(descriptor)
            if not self._same_file_state(before, after):
                raise ValueError("eligibility authority changed while being read")
            current = os.lstat(self._path)
            if not self._same_file_state(after, current):
                raise ValueError("eligibility authority was replaced while being read")
        finally:
            os.close(descriptor)

        return self._parse(contents.decode("utf-8", errors="strict"))

    def _require_nonsymlink_path(self):
        parent = os.lstat(self._path.parent)
        if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
            raise ValueError("eligibility authority parent is invalid")
        target = os.lstat(self._path)
        if stat.S_ISLNK(target.st_mode):
            raise ValueError("eligibility authority is invalid")
        self._require_secure_regular_file(target)

    @staticmethod
    def _require_secure_regular_file(file_stat):
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError("eligibility authority is not a regular file")
        if stat.S_IMODE(file_stat.st_mode) != 0o600:
            raise ValueError("eligibility authority mode is invalid")

    @staticmethod
    def _same_file_state(left, right):
        return (
            left.st_dev == right.st_dev
            and left.st_ino == right.st_ino
            and left.st_size == right.st_size
            and left.st_mtime_ns == right.st_mtime_ns
        )

    def _parse(self, contents):
        if "\r" in contents:
            raise ValueError("eligibility authority contains a carriage return")
        raw_lines = contents.split("\n")
        if contents.endswith("\n"):
            raw_lines.pop()
        addresses = set()
        for raw_line in raw_lines:
            if (
                self._is_kotlin_blank(raw_line)
                or self._trim_kotlin_start(raw_line).startswith("#")
            ):
                continue
            if raw_line.count(":") != 1:
                raise ValueError("eligibility authority entry is invalid")
            address, provider_hash = raw_line.split(":", 1)
            if (
                not self._is_canonical_address(address)
                or not self._is_canonical_hash(provider_hash)
                or address in addresses
            ):
                raise ValueError("eligibility authority entry is invalid")
            addresses.add(address)
        return addresses

    @classmethod
    def _is_kotlin_blank(cls, value):
        return all(cls._is_kotlin_whitespace(character) for character in value)

    @classmethod
    def _trim_kotlin_start(cls, value):
        start = 0
        while start < len(value) and cls._is_kotlin_whitespace(value[start]):
            start += 1
        return value[start:]

    @staticmethod
    def _is_kotlin_whitespace(character):
        code_point = ord(character)
        return (
            0x0009 <= code_point <= 0x000D
            or 0x001C <= code_point <= 0x0020
            or code_point == 0x00A0
            or code_point == 0x1680
            or 0x2000 <= code_point <= 0x200A
            or 0x2028 <= code_point <= 0x2029
            or code_point == 0x202F
            or code_point == 0x205F
            or code_point == 0x3000
        )

    @classmethod
    def _is_canonical_address(cls, address):
        if not isinstance(address, str):
            return False
        if (
            not 1 <= len(address) <= cls.MAX_ADDRESS_LENGTH
            or address != address.lower()
            or any(
                ord(character) < 0x21 or ord(character) > 0x7E
                for character in address
            )
            or address.count("@") != 1
            or any(character in address for character in ':;/\\"()<>')
        ):
            return False
        local_part, domain = address.split("@", 1)
        if (
            not 1 <= len(local_part) <= cls.MAX_LOCAL_PART_LENGTH
            or not cls.LOCAL_PART.fullmatch(local_part)
            or ".." in local_part
            or not 1 <= len(domain) <= cls.MAX_DOMAIN_LENGTH
        ):
            return False
        labels = domain.split(".")
        return bool(labels) and all(cls.DOMAIN_LABEL.fullmatch(label) for label in labels)

    @classmethod
    def _is_canonical_hash(cls, provider_hash):
        if (
            not isinstance(provider_hash, str)
            or not 1 <= len(provider_hash) <= cls.MAX_HASH_LENGTH
        ):
            return False
        match = cls.ARGON2_HASH.fullmatch(provider_hash)
        if not match:
            return False
        parameters = match.group(1, 2, 3)
        if any(not 1 <= int(value) <= 2_147_483_647 for value in parameters):
            return False
        return all(
            cls._is_canonical_phc_base64(value)
            for value in match.group(4, 5)
        )

    @classmethod
    def _is_canonical_phc_base64(cls, value):
        if (
            not 1 <= len(value) <= cls.MAX_ENCODED_SEGMENT_LENGTH
            or len(value) % 4 == 1
        ):
            return False
        padding = "=" * ((4 - len(value) % 4) % 4)
        try:
            decoded = base64.b64decode(value + padding, validate=True)
        except (binascii.Error, ValueError):
            return False
        return base64.b64encode(decoded).decode("ascii").rstrip("=") == value


default_eligibility_reader = EligibilityReader()


def _json_response(handler, data, status=200):
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(json.dumps(data).encode())


def _html_response(handler, html, status=200):
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.end_headers()
    handler.wfile.write(html.encode())


def _redirect(handler, url):
    handler.send_response(302)
    handler.send_header("Location", url)
    handler.end_headers()


def _read_form(handler):
    length = int(handler.headers.get("Content-Length", 0))
    body = handler.rfile.read(length).decode() if length else ""
    return parse_qs(body)


def _apply_test_knobs(handler):
    """Check ?delay= and ?status= query params. Returns True if response was already sent."""
    qs = parse_qs(urlparse(handler.path).query)
    delay = float(qs.get("delay", [0])[0])
    if delay > 0:
        time.sleep(delay)
    forced_status = qs.get("status", [None])[0]
    if forced_status:
        _json_response(handler, {"error": "simulated_server_error"}, int(forced_status))
        return True
    return False


def _make_access_token(username):
    raw = f"valid-{username}"
    token_entry = {
        "username": username,
        "scope": "imap smtp",
        "exp": int(time.time()) + ACCESS_TOKEN_TTL,
    }
    access_tokens[raw] = token_entry
    return raw, token_entry["exp"]


def _make_refresh_token(username, client_id, scope="imap smtp"):
    raw = f"refresh-{username}-{secrets.token_hex(16)}"
    refresh_tokens[raw] = {
        "username": username,
        "client_id": client_id,
        "scope": scope,
    }
    return raw


# ─── Discovery ────────────────────────────────────────────────────────────────

DISCOVERY = {
    "issuer": BASE_URL,
    "authorization_endpoint": f"{BASE_URL}/authorize",
    "token_endpoint": f"{BASE_URL}/token",
    "introspection_endpoint": f"{BASE_URL}/introspect",
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code", "refresh_token"],
    "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
    "scopes_supported": ["imap", "smtp", "imap smtp"],
    "subject_types_supported": ["public"],
}

# ─── Authorization page HTML ──────────────────────────────────────────────────

AUTHORIZE_PAGE = """<!DOCTYPE html>
<html>
<head>
  <title>OAuth2 Mock — Authorize</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 480px; margin: 60px auto; padding: 0 20px; }}
    h1 {{ font-size: 1.3em; }}
    .info {{ background: #f0f0f0; padding: 12px; border-radius: 6px; font-size: 0.9em; margin: 16px 0; }}
    label {{ display: block; margin: 12px 0 4px; font-weight: 600; }}
    input[type=text], input[type=email] {{ width: 100%; padding: 8px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }}
    .buttons {{ margin-top: 20px; display: flex; gap: 10px; }}
    button {{ padding: 10px 24px; border: none; border-radius: 4px; cursor: pointer; font-size: 1em; }}
    .btn-allow {{ background: #2563eb; color: white; }}
    .btn-deny {{ background: #e5e7eb; color: #333; }}
  </style>
</head>
<body>
  <h1>Authorize Application</h1>
  <div class="info">
    <strong>Client:</strong> {client_id}<br>
    <strong>Scope:</strong> {scope}<br>
    <strong>Redirect:</strong> {redirect_uri}
  </div>
  <form method="POST" action="/authorize">
    <input type="hidden" name="client_id" value="{client_id}">
    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
    <input type="hidden" name="scope" value="{scope}">
    <input type="hidden" name="state" value="{state}">
    <input type="hidden" name="response_type" value="code">
    <label for="username">Authorize as (email):</label>
    <input type="email" id="username" name="username" value="dev@local.test" required>
    <div class="buttons">
      <button type="submit" name="action" value="allow" class="btn-allow">Authorize</button>
      <button type="submit" name="action" value="deny" class="btn-deny">Deny</button>
    </div>
  </form>
</body>
</html>"""


# ─── Handler ──────────────────────────────────────────────────────────────────

class OAuthHandler(BaseHTTPRequestHandler):
    eligibility_reader = default_eligibility_reader

    def log_request(self, code="-", size="-"):
        self.log_message("HTTP request completed with status %s", code)

    def log_error(self, format_, *args):
        self.log_message("HTTP protocol error")

    def _is_eligible(self, username):
        try:
            return self.eligibility_reader.is_eligible(username) is True
        except Exception:
            self.log_message("Eligibility authority check failed closed")
            return False

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            _json_response(self, {"status": "ok"})

        elif parsed.path == "/.well-known/oauth-authorization-server":
            _json_response(self, DISCOVERY)

        elif parsed.path == "/authorize":
            if _apply_test_knobs(self):
                return
            qs = parse_qs(parsed.query)
            client_id = qs.get("client_id", [""])[0]
            redirect_uri = qs.get("redirect_uri", [""])[0]
            scope = qs.get("scope", ["imap smtp"])[0]
            state = qs.get("state", [""])[0]

            if not client_id or not redirect_uri:
                _json_response(self, {
                    "error": "invalid_request",
                    "error_description": "client_id and redirect_uri are required",
                }, 400)
                return

            html = AUTHORIZE_PAGE.format(
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                state=state,
            )
            _html_response(self, html)

        else:
            _json_response(self, {"error": "not_found"}, 404)

    def do_POST(self):
        if _apply_test_knobs(self):
            return

        parsed = urlparse(self.path)

        if parsed.path == "/authorize":
            self._handle_authorize_post()
        elif parsed.path == "/token":
            self._handle_token()
        elif parsed.path == "/introspect":
            self._handle_introspect()
        else:
            _json_response(self, {"error": "not_found"}, 404)

    # ── POST /authorize (form submission from consent page) ───────────────

    def _handle_authorize_post(self):
        params = _read_form(self)
        action = params.get("action", [""])[0]
        client_id = params.get("client_id", [""])[0]
        redirect_uri = params.get("redirect_uri", [""])[0]
        scope = params.get("scope", ["imap smtp"])[0]
        state = params.get("state", [""])[0]
        username = params.get("username", [""])[0]

        if action == "deny":
            qs = urlencode({"error": "access_denied", "state": state})
            _redirect(self, f"{redirect_uri}?{qs}")
            return

        if not self._is_eligible(username):
            self.log_message("Authorization denied for an ineligible identity")
            qs = urlencode({"error": "access_denied", "state": state})
            _redirect(self, f"{redirect_uri}?{qs}")
            return

        # Issue authorization code
        code = f"authcode-{secrets.token_hex(20)}"
        auth_codes[code] = {
            "username": username,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "scope": scope,
            "exp": int(time.time()) + AUTH_CODE_TTL,
        }

        self.log_message("Issued authorization code for an eligible identity")

        qs = urlencode({"code": code, "state": state})
        _redirect(self, f"{redirect_uri}?{qs}")

    # ── POST /token ───────────────────────────────────────────────────────

    def _handle_token(self):
        params = _read_form(self)
        grant_type = params.get("grant_type", [""])[0]

        if grant_type == "authorization_code":
            self._token_authorization_code(params)
        elif grant_type == "refresh_token":
            self._token_refresh(params)
        else:
            _json_response(self, {
                "error": "unsupported_grant_type",
                "error_description": "The requested grant type is not supported",
            }, 400)

    def _token_authorization_code(self, params):
        code = params.get("code", [""])[0]
        redirect_uri = params.get("redirect_uri", [""])[0]

        code_entry = auth_codes.pop(code, None)
        if not code_entry:
            _json_response(self, {
                "error": "invalid_grant",
                "error_description": "Authorization code is invalid or already used",
            }, 400)
            return

        if code_entry["exp"] < time.time():
            _json_response(self, {
                "error": "invalid_grant",
                "error_description": "Authorization code has expired",
            }, 400)
            return

        if code_entry["redirect_uri"] != redirect_uri:
            _json_response(self, {
                "error": "invalid_grant",
                "error_description": "redirect_uri does not match",
            }, 400)
            return

        username = code_entry["username"]
        client_id = code_entry["client_id"]
        scope = code_entry["scope"]

        if not self._is_eligible(username):
            _json_response(self, {
                "error": "invalid_grant",
                "error_description": "Authorization grant is no longer valid",
            }, 400)
            return

        access_token, exp = _make_access_token(username)
        refresh_token = _make_refresh_token(username, client_id, scope)

        self.log_message("Issued tokens for an eligible identity")

        _json_response(self, {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_TTL,
            "refresh_token": refresh_token,
            "scope": scope,
        })

    def _token_refresh(self, params):
        refresh_token = params.get("refresh_token", [""])[0]

        entry = refresh_tokens.get(refresh_token)
        if not entry:
            _json_response(self, {
                "error": "invalid_grant",
                "error_description": "Refresh token is invalid or revoked",
            }, 400)
            return

        username = entry["username"]
        scope = entry["scope"]

        if not self._is_eligible(username):
            refresh_tokens.pop(refresh_token, None)
            _json_response(self, {
                "error": "invalid_grant",
                "error_description": "Refresh grant is no longer valid",
            }, 400)
            return

        access_token, exp = _make_access_token(username)

        self.log_message("Refreshed access token for an eligible identity")

        _json_response(self, {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_TTL,
            "refresh_token": refresh_token,  # same refresh token
            "scope": scope,
        })

    # ── POST /introspect (RFC 7662) ──────────────────────────────────────

    def _handle_introspect(self):
        params = _read_form(self)
        token = params.get("token", [""])[0]

        self.log_message("Introspection request")

        # First check the issued tokens store
        if token in access_tokens:
            entry = access_tokens[token]
            eligible = self._is_eligible(entry["username"])
            if entry["exp"] < time.time():
                _json_response(self, {
                    "active": False,
                    "error": "expired_token",
                    "error_description": "The access token has expired",
                })
                return
            if not eligible:
                _json_response(self, {
                    "active": False,
                    "error": "invalid_token",
                    "error_description": "The token is not active",
                })
                return
            _json_response(self, {
                "active": True,
                "username": entry["username"],
                "email": entry["username"],
                "scope": entry["scope"],
                "token_type": "bearer",
                "exp": entry["exp"],
            })
            return

        # Fall back to prefix-based convention for direct testing
        _json_response(self, self._evaluate_token_by_prefix(token))

    def _evaluate_token_by_prefix(self, token: str) -> dict:
        if token.startswith("valid-"):
            username = token[len("valid-"):]
            if not self._is_eligible(username):
                return {
                    "active": False,
                    "error": "invalid_token",
                    "error_description": "The token is not active",
                }
            return {
                "active": True,
                "username": username,
                "email": username,
                "scope": "imap smtp",
                "token_type": "bearer",
                "exp": int(time.time()) + ACCESS_TOKEN_TTL,
            }

        if token.startswith("expired-"):
            username = token[len("expired-"):]
            return {
                "active": False,
                "username": username,
                "error": "expired_token",
                "error_description": "The access token has expired",
            }

        if token.startswith("scope-"):
            username = token[len("scope-"):]
            return {
                "active": False,
                "username": username,
                "error": "insufficient_scope",
                "error_description": "Token does not have the required scope",
            }

        return {
            "active": False,
            "error": "invalid_token",
            "error_description": "The token is not recognised",
        }


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), OAuthHandler)
    print(f"OAuth2 mock server listening on :{PORT}")
    print(f"Discovery: {BASE_URL}/.well-known/oauth-authorization-server")
    print(f"Authorize: {BASE_URL}/authorize")
    print(f"Token:     {BASE_URL}/token")
    print(f"Introspect:{BASE_URL}/introspect")
    server.serve_forever()
