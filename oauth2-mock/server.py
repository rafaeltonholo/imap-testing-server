"""
Mock OAuth2 Authorization Server

Implements a full OAuth2 flow for local dev/testing of IMAP and SMTP clients.

Endpoints:
  GET  /.well-known/oauth-authorization-server  → discovery document
  GET  /authorize   → authorization page (shows consent form, issues auth code)
  POST /token       → exchange auth code or refresh token for access token
  POST /introspect  → validate an access token (RFC 7662)
  GET  /health      → healthcheck
  TCP  :10001       → Postfix socketmap recipient eligibility

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

from enum import Enum
import json
import os
from pathlib import Path
import re
import secrets
import socketserver
import stat
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

PORT = 8080
SOCKETMAP_PORT = 10001
BASE_URL = f"http://localhost:{PORT}"
ELIGIBILITY_FILE = Path("/etc/mail-sandbox-config/users")

# In-memory stores
auth_codes = {}    # code → {username, redirect_uri, client_id, exp}
refresh_tokens = {}  # token → {username, client_id, scope}
access_tokens = {}   # token → {username, scope, exp}

ACCESS_TOKEN_TTL = 3600  # 1 hour
AUTH_CODE_TTL = 60        # 1 minute
MAX_FORM_BODY_BYTES = 16 * 1024
MAX_FORM_FIELDS = 32
MAX_FORM_KEY_CHARACTERS = 128
MAX_FORM_VALUE_CHARACTERS = 8 * 1024
REQUEST_READ_TIMEOUT_SECONDS = 1.0
MAX_SOCKETMAP_REQUEST_BYTES = 512
MAX_SOCKETMAP_CONNECTIONS = 16
MAX_SOCKETMAP_REQUESTS_PER_CONNECTION = 32
SOCKETMAP_REQUEST_TIMEOUT_SECONDS = 1.0
MAX_HTTP_CONNECTIONS = 16
MAX_TEST_DELAY_SECONDS = 5.0
SERVICE_POLL_INTERVAL_SECONDS = 0.1
SERVICE_JOIN_TIMEOUT_SECONDS = 1.0
LOCAL_MAIL_DOMAIN = "local.test"
PROTECTED_LOCAL_PARTS = frozenset({
    "dashboard-management",
    "dashboard-operator-a",
    "dashboard-operator-b",
})
INTROSPECTION_OUTCOMES = frozenset({
    "expired_token",
    "insufficient_scope",
    "invalid_token",
})


class EligibilityResult(Enum):
    ELIGIBLE = "eligible"
    INELIGIBLE = "ineligible"
    UNAVAILABLE = "unavailable"


class InvalidFormRequest(ValueError):
    pass


class InvalidHostAuthority(ValueError):
    pass


class InvalidNetstring(ValueError):
    pass


class NetstringReadTimeout(TimeoutError):
    pass


class EligibilityReader:
    """Read the current Dovecot passwd-file authority without caching it."""

    MAX_FILE_BYTES = 1024 * 1024
    EMPTY_USERDB_FIELDS = "::::::"
    PLAIN_PREFIX = "{PLAIN}"
    LOCAL_PART_PATTERN = (
        r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+"
        r"(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    )
    DOMAIN_LABEL_PATTERN = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
    ADDRESS = re.compile(
        rf"{LOCAL_PART_PATTERN}@{DOMAIN_LABEL_PATTERN}"
        rf"(?:\.{DOMAIN_LABEL_PATTERN})+",
    )

    def __init__(self, path=ELIGIBILITY_FILE):
        self._path = Path(path)

    def eligibility(self, username):
        try:
            addresses = self._read_addresses()
        except (OSError, UnicodeError, ValueError):
            return EligibilityResult.UNAVAILABLE
        if (
            not self._is_canonical_address(username)
            or username not in addresses
        ):
            return EligibilityResult.INELIGIBLE
        return EligibilityResult.ELIGIBLE

    def is_eligible(self, username):
        return self.eligibility(username) is EligibilityResult.ELIGIBLE

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
        addresses = set()
        canonical_lines = []
        for raw_line in contents.splitlines():
            fields = raw_line.split(":")
            if len(fields) != 8 or any(fields[2:]):
                raise ValueError("eligibility authority entry is invalid")
            address, password_field = fields[:2]
            canonical_address = address.casefold()
            if (
                not self._is_canonical_address(address)
                or not self._is_canonical_password_field(password_field)
                or canonical_address in addresses
            ):
                raise ValueError("eligibility authority entry is invalid")
            addresses.add(canonical_address)
            canonical_lines.append(
                f"{address}:{password_field}{self.EMPTY_USERDB_FIELDS}",
            )
        canonical_document = "".join(f"{line}\n" for line in canonical_lines)
        if contents != canonical_document:
            raise ValueError("eligibility authority is not canonically serialized")
        return addresses

    @classmethod
    def _is_canonical_address(cls, address):
        return (
            isinstance(address, str)
            and address == address.casefold()
            and cls.ADDRESS.fullmatch(address) is not None
        )

    @classmethod
    def _is_canonical_password_field(cls, password_field):
        if (
            not isinstance(password_field, str)
            or not password_field.startswith(cls.PLAIN_PREFIX)
        ):
            return False
        password = password_field.removeprefix(cls.PLAIN_PREFIX)
        return bool(password) and not any(
            character in password
            for character in ("\0", "\n", "\r", ":")
        )


default_eligibility_reader = EligibilityReader()


class SocketMapLookup:
    """Resolve Postfix full-recipient socketmap lookups against current authority."""

    def __init__(self, eligibility_reader=default_eligibility_reader):
        self._eligibility_reader = eligibility_reader

    def lookup(self, payload):
        try:
            map_bytes, separator, recipient_bytes = payload.partition(b" ")
        except AttributeError:
            return b"PERM malformed request"
        if not separator or not map_bytes:
            return b"PERM malformed request"
        try:
            map_name = map_bytes.decode("ascii", errors="strict")
        except UnicodeError:
            return b"PERM malformed request"
        if map_name != "eligible":
            return b"PERM unsupported map"
        try:
            recipient = recipient_bytes.decode("ascii", errors="strict")
        except UnicodeError:
            return b"NOTFOUND "
        if not self._is_deliverable_recipient(recipient):
            return b"NOTFOUND "

        try:
            result = self._eligibility_reader.eligibility(recipient)
        except Exception:
            return b"TEMP eligibility authority unavailable"
        if result is EligibilityResult.ELIGIBLE:
            return b"OK 1"
        if result is EligibilityResult.INELIGIBLE:
            return b"NOTFOUND "
        return b"TEMP eligibility authority unavailable"

    @staticmethod
    def _is_deliverable_recipient(recipient):
        if not EligibilityReader._is_canonical_address(recipient):
            return False
        local_part, domain = recipient.split("@", 1)
        base_local_part = local_part.split("+", 1)[0]
        return (
            domain == LOCAL_MAIL_DOMAIN
            and base_local_part not in PROTECTED_LOCAL_PARTS
        )


def _encode_netstring(payload):
    return str(len(payload)).encode("ascii") + b":" + payload + b","


def _read_netstring(connection, maximum_length, timeout_seconds):
    deadline = time.monotonic() + timeout_seconds
    length_bytes = bytearray()

    while True:
        try:
            byte = _receive_before_deadline(connection, 1, deadline)
        except NetstringReadTimeout:
            if not length_bytes:
                return None
            raise InvalidNetstring() from None
        if not byte:
            if not length_bytes:
                return None
            raise InvalidNetstring()
        if byte == b":":
            break
        if byte < b"0" or byte > b"9":
            raise InvalidNetstring()
        length_bytes.extend(byte)
        if len(length_bytes) > len(str(maximum_length)):
            raise InvalidNetstring()

    if (
        not length_bytes
        or len(length_bytes) > 1
        and length_bytes[0] == ord("0")
    ):
        raise InvalidNetstring()
    length = int(length_bytes)
    if length > maximum_length:
        raise InvalidNetstring()

    payload = bytearray()
    while len(payload) < length:
        try:
            chunk = _receive_before_deadline(
                connection,
                length - len(payload),
                deadline,
            )
        except NetstringReadTimeout:
            raise InvalidNetstring() from None
        if not chunk:
            raise InvalidNetstring()
        payload.extend(chunk)
    try:
        terminator = _receive_before_deadline(connection, 1, deadline)
    except NetstringReadTimeout:
        raise InvalidNetstring() from None
    if terminator != b",":
        raise InvalidNetstring()
    return bytes(payload)


def _receive_before_deadline(connection, maximum_bytes, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise NetstringReadTimeout()
    try:
        connection.settimeout(remaining)
        return connection.recv(maximum_bytes)
    except TimeoutError:
        raise NetstringReadTimeout() from None
    except OSError:
        raise InvalidNetstring() from None


class SocketMapRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        for _ in range(MAX_SOCKETMAP_REQUESTS_PER_CONNECTION):
            try:
                payload = _read_netstring(
                    self.request,
                    MAX_SOCKETMAP_REQUEST_BYTES,
                    self.server.request_timeout_seconds,
                )
            except InvalidNetstring:
                self.server.log_message(
                    "Socketmap lookup outcome=protocol-error",
                )
                self._send_response(b"PERM malformed request")
                return
            if payload is None:
                return
            response = self.server.lookup.lookup(payload)
            self.server.log_message(
                f"Socketmap lookup outcome={_socketmap_outcome(response)}",
            )
            if not self._send_response(response):
                return

    def _send_response(self, payload):
        try:
            self.request.sendall(_encode_netstring(payload))
        except OSError:
            return False
        return True


def _socketmap_outcome(response):
    for outcome in ("OK", "NOTFOUND", "TEMP"):
        if response.startswith(f"{outcome} ".encode("ascii")):
            return outcome
    return "protocol-error"


class SocketMapServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(
        self,
        server_address,
        lookup,
        log_message=print,
        request_timeout_seconds=SOCKETMAP_REQUEST_TIMEOUT_SECONDS,
    ):
        self.lookup = lookup
        self.log_message = log_message
        self.request_timeout_seconds = request_timeout_seconds
        self._connection_slots = threading.BoundedSemaphore(
            MAX_SOCKETMAP_CONNECTIONS,
        )
        self._active_connection_lock = threading.Lock()
        self._active_connection_count = 0
        self._stop_requested = None
        super().__init__(server_address, SocketMapRequestHandler)

    @property
    def active_connection_count(self):
        with self._active_connection_lock:
            return self._active_connection_count

    def process_request(self, request, client_address):
        if not self._connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self._active_connection_lock:
            self._active_connection_count += 1
        try:
            super().process_request(request, client_address)
        except Exception:
            self._release_connection_slot()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release_connection_slot()

    def handle_error(self, request, client_address):
        self.log_message("Socketmap lookup outcome=protocol-error")

    def serve_until(self, stop_requested):
        self._stop_requested = stop_requested
        try:
            try:
                self.serve_forever(
                    poll_interval=SERVICE_POLL_INTERVAL_SECONDS,
                )
            except _ServiceStopRequested:
                pass
        finally:
            self._stop_requested = None

    def service_actions(self):
        super().service_actions()
        stop_requested = self._stop_requested
        if stop_requested is not None and stop_requested.is_set():
            raise _ServiceStopRequested()

    def _release_connection_slot(self):
        with self._active_connection_lock:
            self._active_connection_count -= 1
        self._connection_slots.release()


class _PeerServerStopped(RuntimeError):
    pass


class _ServiceStopRequested(RuntimeError):
    pass


class SupervisedHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, server_address, request_handler_class):
        self._connection_slots = threading.BoundedSemaphore(
            MAX_HTTP_CONNECTIONS,
        )
        self._active_connection_lock = threading.Lock()
        self._active_connection_count = 0
        super().__init__(server_address, request_handler_class)

    @property
    def active_connection_count(self):
        with self._active_connection_lock:
            return self._active_connection_count

    def process_request(self, request, client_address):
        if not self._connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self._active_connection_lock:
            self._active_connection_count += 1
        try:
            super().process_request(request, client_address)
        except Exception:
            self._release_connection_slot()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release_connection_slot()

    def serve_until(self, peer_stopped):
        self._peer_stopped = peer_stopped
        try:
            self.serve_forever(
                poll_interval=SERVICE_POLL_INTERVAL_SECONDS,
            )
        finally:
            self._peer_stopped = None

    def service_actions(self):
        super().service_actions()
        peer_stopped = getattr(self, "_peer_stopped", None)
        if peer_stopped is not None and peer_stopped.is_set():
            raise _PeerServerStopped()

    def _release_connection_slot(self):
        with self._active_connection_lock:
            self._active_connection_count -= 1
        self._connection_slots.release()


def build_servers(
    eligibility_reader=default_eligibility_reader,
    http_server_factory=SupervisedHTTPServer,
    socketmap_server_factory=SocketMapServer,
    http_address=("0.0.0.0", PORT),
    socketmap_address=("0.0.0.0", SOCKETMAP_PORT),
):
    lookup = SocketMapLookup(eligibility_reader)
    socketmap_server = socketmap_server_factory(socketmap_address, lookup)

    class ServiceOAuthHandler(OAuthHandler):
        pass

    ServiceOAuthHandler.eligibility_reader = eligibility_reader
    try:
        http_server = http_server_factory(http_address, ServiceOAuthHandler)
    except Exception:
        socketmap_server.server_close()
        raise
    return http_server, socketmap_server


def serve_services(http_server, socketmap_server):
    stopping = threading.Event()
    socketmap_stopped = threading.Event()
    socketmap_failures = []

    def run_socketmap():
        failure = None
        try:
            socketmap_server.serve_until(stopping)
        except BaseException as exception:
            failure = exception
        else:
            if not stopping.is_set():
                failure = RuntimeError(
                    "Socketmap server stopped unexpectedly",
                )
        finally:
            if failure is not None:
                socketmap_failures.append(failure)
            socketmap_stopped.set()

    socketmap_thread = threading.Thread(
        target=run_socketmap,
        name="postfix-socketmap",
        daemon=True,
    )
    socketmap_thread.start()
    http_failure = None
    try:
        http_server.serve_until(socketmap_stopped)
        if not socketmap_stopped.is_set():
            http_failure = RuntimeError(
                "HTTP server stopped unexpectedly",
            )
    except _PeerServerStopped:
        pass
    except BaseException as exception:
        http_failure = exception
    finally:
        stopping.set()
        socketmap_thread.join(SERVICE_JOIN_TIMEOUT_SECONDS)
        socketmap_join_failed = socketmap_thread.is_alive()
        http_server.server_close()
        socketmap_server.server_close()

    if socketmap_join_failed:
        raise RuntimeError(
            "Socketmap server did not stop within the shutdown bound",
        )
    if socketmap_failures:
        raise socketmap_failures[0]
    if http_failure is not None:
        raise http_failure


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
    content_lengths = _header_values(handler.headers, "Content-Length")
    if len(content_lengths) != 1:
        raise InvalidFormRequest()
    encoded_length = content_lengths[0]
    if (
        not encoded_length
        or len(encoded_length) > 10
        or any(character < "0" or character > "9" for character in encoded_length)
    ):
        raise InvalidFormRequest()
    length = int(encoded_length)
    if length > MAX_FORM_BODY_BYTES:
        raise InvalidFormRequest()

    body_bytes = _read_exact_form_body(handler, length)
    try:
        body = body_bytes.decode("utf-8", errors="strict")
        fields = parse_qs(
            body,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=MAX_FORM_FIELDS,
            separator="&",
        )
    except (UnicodeError, ValueError):
        raise InvalidFormRequest() from None
    if (
        sum(len(values) for values in fields.values()) > MAX_FORM_FIELDS
        or any(
            len(key) > MAX_FORM_KEY_CHARACTERS
            or any(
                len(value) > MAX_FORM_VALUE_CHARACTERS
                for value in values
            )
            for key, values in fields.items()
        )
    ):
        raise InvalidFormRequest()
    return fields


def _header_values(headers, name):
    get_all = getattr(headers, "get_all", None)
    if get_all is not None:
        return get_all(name, [])
    value = headers.get(name)
    return [] if value is None else [value]


def _read_exact_form_body(handler, length):
    if length == 0:
        return b""
    deadline = time.monotonic() + REQUEST_READ_TIMEOUT_SECONDS
    remaining = length
    chunks = []
    connection = getattr(handler, "connection", None)
    try:
        while remaining:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                raise InvalidFormRequest()
            if connection is not None:
                connection.settimeout(timeout)
            reader = getattr(handler.rfile, "read1", handler.rfile.read)
            try:
                chunk = reader(remaining)
            except (OSError, TimeoutError):
                raise InvalidFormRequest() from None
            if not chunk:
                raise InvalidFormRequest()
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        if connection is not None:
            try:
                connection.settimeout(REQUEST_READ_TIMEOUT_SECONDS)
            except OSError:
                pass
    return b"".join(chunks)


def _apply_test_knobs(handler):
    """Check ?delay= and ?status= query params. Returns True if response was already sent."""
    qs = parse_qs(urlparse(handler.path).query)
    try:
        delay = float(qs.get("delay", [0])[0])
    except (TypeError, ValueError):
        delay = 0
    if delay == delay and delay > 0:
        time.sleep(min(delay, MAX_TEST_DELAY_SECONDS))
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


def _request_origin(headers):
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        authorities = get_all("Host", [])
    else:
        authority = headers.get("Host")
        authorities = [] if authority is None else [authority]
    if len(authorities) != 1:
        raise InvalidHostAuthority()

    authority = authorities[0]
    if not isinstance(authority, str) or authority != authority.strip():
        raise InvalidHostAuthority()
    try:
        parsed = urlparse(f"//{authority}")
        port = parsed.port
    except ValueError:
        raise InvalidHostAuthority() from None
    if (
        not authority
        or parsed.netloc != authority
        or parsed.path
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or not _valid_discovery_host(parsed.hostname)
        or port is None
        or not 1 <= port <= 65535
    ):
        raise InvalidHostAuthority()
    return f"http://{authority}"


def _valid_discovery_host(host):
    if not host:
        return False
    if ":" in host:
        return bool(re.fullmatch(r"[0-9a-fA-F:.]+", host))
    if len(host) > 253:
        return False
    labels = host.rstrip(".").split(".")
    return all(
        label
        and len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    )


def _discovery_document(origin):
    return {
        "issuer": origin,
        "authorization_endpoint": f"{origin}/authorize",
        "token_endpoint": f"{origin}/token",
        "introspection_endpoint": f"{origin}/introspect",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
        ],
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

    def setup(self):
        self.request.settimeout(REQUEST_READ_TIMEOUT_SECONDS)
        super().setup()

    def log_request(self, code="-", size="-"):
        self.log_message("HTTP request completed with status %s", code)

    def log_error(self, format_, *args):
        self.log_message("HTTP protocol error")

    def _eligibility(self, username):
        try:
            result = self.eligibility_reader.eligibility(username)
            if not isinstance(result, EligibilityResult):
                raise TypeError("Invalid eligibility result")
            return result
        except Exception:
            self.log_message("Eligibility authority check failed closed")
            return EligibilityResult.UNAVAILABLE

    def _is_eligible(self, username):
        return self._eligibility(username) is EligibilityResult.ELIGIBLE

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            _json_response(self, {"status": "ok"})

        elif parsed.path == "/.well-known/oauth-authorization-server":
            try:
                origin = _request_origin(self.headers)
            except InvalidHostAuthority:
                _json_response(self, {"error": "invalid_request"}, 400)
                return
            _json_response(self, _discovery_document(origin))

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

        try:
            if parsed.path == "/authorize":
                self._handle_authorize_post()
            elif parsed.path == "/token":
                self._handle_token()
            elif parsed.path == "/introspect":
                self._handle_introspect()
            else:
                _json_response(self, {"error": "not_found"}, 404)
        except InvalidFormRequest:
            self.log_message("Rejected invalid request form")
            _json_response(self, {
                "error": "invalid_request",
                "error_description": "Request form is invalid",
            }, 400)

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

        eligibility = self._eligibility(username)
        if eligibility is EligibilityResult.INELIGIBLE:
            refresh_tokens.pop(refresh_token, None)
        if eligibility is not EligibilityResult.ELIGIBLE:
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

        # First check the issued tokens store
        if token in access_tokens:
            entry = access_tokens[token]
            eligible = self._is_eligible(entry["username"])
            if entry["exp"] < time.time():
                result = {
                    "active": False,
                    "error": "expired_token",
                    "error_description": "The access token has expired",
                }
            elif not eligible:
                result = {
                    "active": False,
                    "error": "invalid_token",
                    "error_description": "The token is not active",
                }
            else:
                result = {
                    "active": True,
                    "username": entry["username"],
                    "email": entry["username"],
                    "scope": entry["scope"],
                    "token_type": "bearer",
                    "exp": entry["exp"],
                }
        else:
            # Fall back to prefix-based convention for direct testing.
            result = self._evaluate_token_by_prefix(token)

        self._log_introspection_result(result)
        _json_response(self, result)

    def _log_introspection_result(self, result):
        username = result.get("username")
        identity = (
            username
            if EligibilityReader._is_canonical_address(username)
            else "unknown"
        )
        if result.get("active") is True:
            outcome = "active"
        else:
            error = result.get("error")
            outcome = error if error in INTROSPECTION_OUTCOMES else "inactive"
        self.log_message(
            "Introspection identity=%s outcome=%s",
            identity,
            outcome,
        )

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
    http_server, socketmap_server = build_servers()
    print(f"OAuth2 mock server listening on :{PORT}")
    print(f"Postfix socketmap listening internally on :{SOCKETMAP_PORT}")
    print(f"Discovery: {BASE_URL}/.well-known/oauth-authorization-server")
    print(f"Authorize: {BASE_URL}/authorize")
    print(f"Token:     {BASE_URL}/token")
    print(f"Introspect:{BASE_URL}/introspect")
    serve_services(http_server, socketmap_server)
