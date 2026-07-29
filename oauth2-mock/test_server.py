import http.client
import io
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import types
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlencode, urlparse


SERVER_PATH = Path(__file__).with_name("server.py")
KOTLIN_WHITESPACE_FIXTURE_PATH = SERVER_PATH.with_name(
    "kotlin-whitespace-fixture.txt",
)
SERVER_SPEC = importlib.util.spec_from_file_location("oauth2_mock_server", SERVER_PATH)
server = importlib.util.module_from_spec(SERVER_SPEC)
SERVER_SPEC.loader.exec_module(server)


VALID_HASH = (
    "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=1"
    "$c2FsdA$ZGlnZXN0"
)


class MutableEligibilityReader:
    def __init__(self, *eligible):
        self.eligible = set(eligible)

    def eligibility(self, username):
        if username in self.eligible:
            return server.EligibilityResult.ELIGIBLE
        return server.EligibilityResult.INELIGIBLE


class OAuthServerTest(unittest.TestCase):
    def setUp(self):
        server.auth_codes.clear()
        server.refresh_tokens.clear()
        server.access_tokens.clear()
        self.reader = MutableEligibilityReader("eligible@local.test")
        self.logs = []
        logs = self.logs
        reader = self.reader

        class TestHandler(server.OAuthHandler):
            eligibility_reader = reader

            def log_message(self, format_, *args):
                logs.append(format_ % args)

        self.handler_class = TestHandler

    def tearDown(self):
        server.auth_codes.clear()
        server.refresh_tokens.clear()
        server.access_tokens.clear()

    def test_authorization_rejects_noneligible_username(self):
        response = self.post(
            "/authorize",
            {
                "action": "allow",
                "client_id": "test-client",
                "redirect_uri": "http://client.invalid/callback",
                "scope": "imap smtp",
                "state": "opaque-state",
                "response_type": "code",
                "username": "absent@local.test",
            },
        )

        self.assertEqual(302, response.status)
        redirect = parse_qs(urlparse(response.headers["Location"]).query)
        self.assertEqual(["access_denied"], redirect["error"])
        self.assertEqual(["opaque-state"], redirect["state"])
        self.assertNotIn("code", redirect)
        self.assertEqual({}, server.auth_codes)

    def test_authorization_code_exchange_rechecks_eligibility(self):
        code = self.issue_authorization_code()
        self.reader.eligible.clear()

        response = self.post(
            "/token",
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://client.invalid/callback",
            },
        )

        self.assertEqual(400, response.status)
        self.assertEqual("invalid_grant", response.json()["error"])
        self.assertEqual({}, server.access_tokens)
        self.assertEqual({}, server.refresh_tokens)

    def test_refresh_exchange_rechecks_eligibility_and_revokes_deleted_identity(self):
        submitted_refresh = "refresh-sensitive-value"
        server.refresh_tokens[submitted_refresh] = {
            "username": "eligible@local.test",
            "client_id": "test-client",
            "scope": "imap smtp",
        }
        self.reader.eligible.clear()

        response = self.post(
            "/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": submitted_refresh,
            },
        )

        self.assertEqual(400, response.status)
        self.assertEqual("invalid_grant", response.json()["error"])
        self.assertNotIn(submitted_refresh, response.body)
        self.assertNotIn(submitted_refresh, server.refresh_tokens)
        self.assertEqual({}, server.access_tokens)

    def test_stored_and_valid_prefix_tokens_recheck_eligibility(self):
        stored_token = "stored-sensitive-bearer"
        server.access_tokens[stored_token] = {
            "username": "absent@local.test",
            "scope": "imap smtp",
            "exp": int(time.time()) + 300,
        }

        stored = self.post("/introspect", {"token": stored_token})
        prefix = self.post(
            "/introspect",
            {"token": "valid-absent@local.test"},
        )
        eligible_prefix = self.post(
            "/introspect",
            {"token": "valid-eligible@local.test"},
        )

        self.assertFalse(stored.json()["active"])
        self.assertFalse(prefix.json()["active"])
        self.assertTrue(eligible_prefix.json()["active"])
        self.assertEqual("eligible@local.test", eligible_prefix.json()["username"])

    def test_deleted_identity_becomes_inactive_without_restarting_server(self):
        token = "stored-deletion-check"
        server.access_tokens[token] = {
            "username": "eligible@local.test",
            "scope": "imap smtp",
            "exp": int(time.time()) + 300,
        }

        before = self.post("/introspect", {"token": token})
        self.reader.eligible.clear()
        after = self.post("/introspect", {"token": token})

        self.assertTrue(before.json()["active"])
        self.assertFalse(after.json()["active"])

    def test_expired_scope_and_invalid_test_token_semantics_remain(self):
        expired = self.post(
            "/introspect",
            {"token": "expired-anyone@local.test"},
        ).json()
        scope = self.post(
            "/introspect",
            {"token": "scope-anyone@local.test"},
        ).json()
        invalid = self.post("/introspect", {"token": "not-a-token"}).json()

        self.assertFalse(expired["active"])
        self.assertEqual("expired_token", expired["error"])
        self.assertFalse(scope["active"])
        self.assertEqual("insufficient_scope", scope["error"])
        self.assertFalse(invalid["active"])
        self.assertEqual("invalid_token", invalid["error"])

    def test_submitted_secrets_are_absent_from_error_responses_and_logs(self):
        unknown_code = "authcode-sensitive-value"
        unknown_refresh = "refresh-sensitive-value"
        unknown_bearer = "bearer-sensitive-value"
        submitted_password = "password-sensitive-value"
        disguised_secret_grant = "bearer-sensitive-grant-value"

        responses = [
            self.post(
                "/token",
                {
                    "grant_type": "authorization_code",
                    "code": unknown_code,
                    "redirect_uri": "http://client.invalid/callback",
                },
            ),
            self.post(
                "/token",
                {
                    "grant_type": "refresh_token",
                    "refresh_token": unknown_refresh,
                },
            ),
            self.post("/introspect", {"token": unknown_bearer}),
            self.post(
                "/authorize",
                {
                    "action": "allow",
                    "client_id": "test-client",
                    "redirect_uri": "http://client.invalid/callback",
                    "username": "absent@local.test",
                    "password": submitted_password,
                },
            ),
            self.post(
                "/token",
                {"grant_type": disguised_secret_grant},
            ),
        ]

        combined_responses = "\n".join(
            response.body + "\n" + json.dumps(response.headers, sort_keys=True)
            for response in responses
        )
        combined_logs = "\n".join(self.logs)
        for secret in (
            unknown_code,
            unknown_refresh,
            unknown_bearer,
            submitted_password,
            disguised_secret_grant,
        ):
            self.assertNotIn(secret, combined_responses)
            self.assertNotIn(secret, combined_logs)

    def test_successful_protocol_secrets_are_not_written_to_logs(self):
        disguised_client_secret = "bearer-sensitive-client-value"
        authorization_code = self.issue_authorization_code(
            client_id=disguised_client_secret,
        )
        token_response = self.post(
            "/token",
            {
                "grant_type": "authorization_code",
                "code": authorization_code,
                "redirect_uri": "http://client.invalid/callback",
            },
        )
        self.assertEqual(200, token_response.status)
        tokens = token_response.json()
        access_token = tokens["access_token"]
        refresh_token = tokens["refresh_token"]

        introspection = self.post("/introspect", {"token": access_token})
        self.assertTrue(introspection.json()["active"])

        combined_logs = "\n".join(self.logs)
        for secret in (
            authorization_code,
            access_token,
            refresh_token,
            disguised_client_secret,
        ):
            self.assertNotIn(secret, combined_logs)

    def test_request_logging_omits_query_values(self):
        query_secret = "bearer-sensitive-query-value"
        protocol_error_secret = "refresh-sensitive-protocol-value"
        handler = self.handler_class.__new__(self.handler_class)
        handler.command = "POST"
        handler.path = f"/introspect?token={query_secret}"
        handler.requestline = f"POST {handler.path} HTTP/1.1"

        handler.log_request(200)
        handler.log_error("bad request %s", protocol_error_secret)

        combined_logs = "\n".join(self.logs)
        self.assertNotIn(query_secret, combined_logs)
        self.assertNotIn(protocol_error_secret, combined_logs)

    def test_eligibility_reader_failure_blocks_every_oauth_transition(self):
        code = self.issue_authorization_code()
        refresh = "refresh-authority-failure"
        bearer = "bearer-authority-failure"
        server.refresh_tokens[refresh] = {
            "username": "eligible@local.test",
            "client_id": "test-client",
            "scope": "imap smtp",
        }
        server.access_tokens[bearer] = {
            "username": "eligible@local.test",
            "scope": "imap smtp",
            "exp": int(time.time()) + 300,
        }

        class FailingReader:
            def eligibility(self, username):
                raise OSError("simulated authority failure")

        self.handler_class.eligibility_reader = FailingReader()
        authorization = self.post(
            "/authorize",
            {
                "action": "allow",
                "client_id": "test-client",
                "redirect_uri": "http://client.invalid/callback",
                "state": "opaque-state",
                "username": "eligible@local.test",
            },
        )
        code_exchange = self.post(
            "/token",
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://client.invalid/callback",
            },
        )
        refresh_exchange = self.post(
            "/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh,
            },
        )
        stored = self.post("/introspect", {"token": bearer})
        prefix = self.post(
            "/introspect",
            {"token": "valid-eligible@local.test"},
        )

        authorization_query = parse_qs(
            urlparse(authorization.headers["Location"]).query,
        )
        self.assertEqual(["access_denied"], authorization_query["error"])
        self.assertEqual(400, code_exchange.status)
        self.assertEqual("invalid_grant", code_exchange.json()["error"])
        self.assertNotIn(code, server.auth_codes)
        self.assertEqual(400, refresh_exchange.status)
        self.assertEqual("invalid_grant", refresh_exchange.json()["error"])
        self.assertIn(refresh, server.refresh_tokens)
        self.assertNotIn("valid-eligible@local.test", server.access_tokens)
        self.assertFalse(stored.json()["active"])
        self.assertFalse(prefix.json()["active"])

    def issue_authorization_code(self, client_id="test-client"):
        response = self.post(
            "/authorize",
            {
                "action": "allow",
                "client_id": client_id,
                "redirect_uri": "http://client.invalid/callback",
                "scope": "imap smtp",
                "state": "opaque-state",
                "response_type": "code",
                "username": "eligible@local.test",
            },
        )
        self.assertEqual(302, response.status)
        redirect = parse_qs(urlparse(response.headers["Location"]).query)
        return redirect["code"][0]

    def post(self, path, params):
        body = urlencode(params)
        handler = self.handler_class.__new__(self.handler_class)
        handler.path = path
        handler.headers = {
            "Content-Length": str(len(body.encode("utf-8"))),
            "Content-Type": "application/x-www-form-urlencoded",
        }
        handler.rfile = io.BytesIO(body.encode("utf-8"))
        handler.wfile = io.BytesIO()
        handler.response_status = None
        handler.response_headers = {}

        def send_response(instance, status):
            instance.response_status = status

        def send_header(instance, name, value):
            instance.response_headers[name] = value

        def end_headers(instance):
            return None

        handler.send_response = types.MethodType(send_response, handler)
        handler.send_header = types.MethodType(send_header, handler)
        handler.end_headers = types.MethodType(end_headers, handler)
        handler.do_POST()
        return HttpResponse(
            handler.response_status,
            handler.response_headers,
            handler.wfile.getvalue().decode("utf-8"),
        )


class EligibilityReaderTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.authority = self.root / "users"

    def tearDown(self):
        self.temporary.cleanup()

    def test_reads_canonical_entries_comments_and_blank_lines(self):
        self.write_authority(
            "# generated authority\n"
            "\n"
            f"eligible@local.test:{VALID_HASH}\n"
            f"second.user+tag@local.test:{VALID_HASH}\n"
        )
        reader = server.EligibilityReader(self.authority)

        self.assertTrue(reader.is_eligible("eligible@local.test"))
        self.assertTrue(reader.is_eligible("second.user+tag@local.test"))
        self.assertFalse(reader.is_eligible("absent@local.test"))
        self.assertFalse(reader.is_eligible("ELIGIBLE@local.test"))

    def test_malformed_authority_fails_closed_for_every_identity(self):
        malformed_authorities = (
            f"eligible@local.test:{VALID_HASH}\r\n",
            f"ELIGIBLE@local.test:{VALID_HASH}\n",
            "eligible@local.test:{ARGON2ID}garbage\n",
            (
                "eligible@local.test:"
                "{ARGON2ID}$argon2id$v=19$m=2147483648,t=3,p=1"
                "$c2FsdA$ZGlnZXN0\n"
            ),
            (
                f"eligible@local.test:{VALID_HASH}\n"
                f"eligible@local.test:{VALID_HASH}\n"
            ),
            f"eligible@local.test:{VALID_HASH}:extra\n",
        )

        for index, contents in enumerate(malformed_authorities):
            with self.subTest(index=index):
                self.write_authority(contents)
                reader = server.EligibilityReader(self.authority)
                self.assertFalse(reader.is_eligible("eligible@local.test"))

    def test_symlink_authority_fails_closed(self):
        real_authority = self.root / "real-users"
        real_authority.write_text(
            f"eligible@local.test:{VALID_HASH}\n",
            encoding="utf-8",
        )
        os.chmod(real_authority, 0o600)
        self.authority.symlink_to(real_authority)

        reader = server.EligibilityReader(self.authority)

        self.assertFalse(reader.is_eligible("eligible@local.test"))

    def test_each_decision_reads_the_current_authority(self):
        self.write_authority(f"eligible@local.test:{VALID_HASH}\n")
        reader = server.EligibilityReader(self.authority)
        self.assertTrue(reader.is_eligible("eligible@local.test"))

        self.write_authority("")

        self.assertFalse(reader.is_eligible("eligible@local.test"))

    def test_explicit_result_distinguishes_absence_from_unavailable_authority(self):
        self.write_authority(f"eligible@local.test:{VALID_HASH}\n")
        reader = server.EligibilityReader(self.authority)

        self.assertEqual(
            server.EligibilityResult.ELIGIBLE,
            reader.eligibility("eligible@local.test"),
        )
        self.assertEqual(
            server.EligibilityResult.INELIGIBLE,
            reader.eligibility("absent@local.test"),
        )
        with mock.patch.object(reader, "_same_file_state", return_value=False):
            self.assertEqual(
                server.EligibilityResult.UNAVAILABLE,
                reader.eligibility("eligible@local.test"),
            )

    def test_unreadable_authority_fails_closed(self):
        self.write_authority(f"eligible@local.test:{VALID_HASH}\n")
        real_open = os.open

        def deny_authority(path, flags, *args, **kwargs):
            if Path(path) == self.authority:
                raise PermissionError("simulated unreadable authority")
            return real_open(path, flags, *args, **kwargs)

        reader = server.EligibilityReader(self.authority)
        with mock.patch.object(server.os, "open", side_effect=deny_authority):
            self.assertFalse(reader.is_eligible("eligible@local.test"))

    def test_missing_and_group_readable_authorities_fail_closed(self):
        reader = server.EligibilityReader(self.authority)
        self.assertFalse(reader.is_eligible("eligible@local.test"))

        self.write_authority(f"eligible@local.test:{VALID_HASH}\n")
        os.chmod(self.authority, 0o640)
        self.assertFalse(reader.is_eligible("eligible@local.test"))

    def test_nonregular_authority_fails_closed_without_blocking(self):
        os.mkfifo(self.authority, mode=0o600)
        reader = server.EligibilityReader(self.authority)

        self.assertFalse(reader.is_eligible("eligible@local.test"))

    def test_invalid_utf8_and_oversized_authorities_fail_closed(self):
        reader = server.EligibilityReader(self.authority)
        for contents in (
            b"\xff",
            b" " * (server.EligibilityReader.MAX_FILE_BYTES + 1),
        ):
            with self.subTest(size=len(contents)):
                self.authority.unlink(missing_ok=True)
                self.authority.write_bytes(contents)
                os.chmod(self.authority, 0o600)
                self.assertFalse(reader.is_eligible("eligible@local.test"))

    def test_blank_and_comment_parsing_matches_kotlin_whitespace_fixture(self):
        records = []
        for line in KOTLIN_WHITESPACE_FIXTURE_PATH.read_text(
            encoding="ascii",
        ).splitlines():
            if not line or line.startswith("#"):
                continue
            encoded, expected = line.split(" ")
            bounds = [int(value, 16) for value in encoded.split("-")]
            records.append(
                (range(bounds[0], bounds[-1] + 1), expected == "true"),
            )
        expected_whitespace = {
            code_point
            for code_points, expected in records
            if expected
            for code_point in code_points
        }
        for code_points, expected in records:
            if not expected:
                self.assertTrue(
                    expected_whitespace.isdisjoint(code_points),
                    "conflicting Kotlin whitespace fixture record",
                )

        for code_point in range(0x10000):
            self.assertEqual(
                code_point in expected_whitespace,
                server.EligibilityReader._is_kotlin_whitespace(
                    chr(code_point),
                ),
                f"unexpected classification for U+{code_point:04X}",
            )

        for prefix in ("\u0009", "\u00A0", "\u2007", "\u3000"):
            with self.subTest(accepted_comment=ord(prefix)):
                self.write_authority(
                    f"{prefix}\n"
                    f"{prefix}# Kotlin whitespace comment\n"
                    f"eligible@local.test:{VALID_HASH}\n",
                )
                reader = server.EligibilityReader(self.authority)
                self.assertTrue(reader.is_eligible("eligible@local.test"))

        for malformed in (
            "\u0085",
            "\u0085# Python-only whitespace must not start a comment",
            "\u180E# non-whitespace must not start a comment",
            "\uFEFF# non-whitespace must not start a comment",
        ):
            with self.subTest(rejected_prefix=f"U+{ord(malformed[0]):04X}"):
                self.write_authority(
                    f"{malformed}\n"
                    f"eligible@local.test:{VALID_HASH}\n",
                )
                reader = server.EligibilityReader(self.authority)
                self.assertFalse(reader.is_eligible("eligible@local.test"))

    def write_authority(self, contents):
        self.authority.unlink(missing_ok=True)
        self.authority.write_text(contents, encoding="utf-8")
        os.chmod(self.authority, 0o600)


class OAuthComposeTest(unittest.TestCase):
    def test_oauth_mounts_only_the_eligibility_directory_read_only(self):
        self.assertEqual(
            Path("/etc/dovecot/runtime/users"),
            server.ELIGIBILITY_FILE,
        )
        compose = SERVER_PATH.parent.parent.joinpath("docker-compose.yml").read_text(
            encoding="utf-8",
        )
        lines = compose.splitlines()
        service_start = lines.index("  oauth2-mock:")
        service_end = next(
            (
                index
                for index in range(service_start + 1, len(lines))
                if lines[index].startswith("  ")
                and not lines[index].startswith("    ")
                and lines[index].endswith(":")
            ),
            len(lines),
        )
        service = "\n".join(lines[service_start:service_end])

        self.assertIn(
            (
                "- ./debug-dashboard/.runtime/dovecot:"
                "/etc/dovecot/runtime:ro"
            ),
            service,
        )
        self.assertNotIn(".runtime/secrets", service)
        self.assertNotIn(".runtime/dovecot-operator", service)
        self.assertNotIn("/etc/dovecot/runtime/users:", service)


class ActualHttpFormBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.logs = []
        logs = self.logs

        class TestHandler(server.OAuthHandler):
            eligibility_reader = MutableEligibilityReader("eligible@local.test")

            def log_message(self, format_, *args):
                logs.append(format_ % args)

        self.httpd = server.HTTPServer(("127.0.0.1", 0), TestHandler)
        self.thread = threading.Thread(
            target=self.httpd.serve_forever,
            name="oauth-actual-http-test",
            daemon=True,
        )
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive(), "HTTP test server did not stop")

    def test_malformed_forms_are_fixed_400_and_server_remains_healthy(self):
        excess_fields = "&".join(f"field{index}=x" for index in range(33)).encode()
        oversized_value = b"token=" + (b"x" * (8 * 1024 + 1))
        cases = (
            (
                "missing",
                b"",
                b"token=x",
            ),
            (
                "negative",
                b"Content-Length: -1\r\n",
                b"token=negative-sensitive-value",
            ),
            (
                "non-decimal",
                b"Content-Length: 7x\r\n",
                b"token=x",
            ),
            (
                "signed-positive",
                b"Content-Length: +7\r\n",
                b"token=x",
            ),
            (
                "duplicate",
                b"Content-Length: 7\r\nContent-Length: 7\r\n",
                b"token=x",
            ),
            (
                "huge",
                b"Content-Length: 999999999999999999999999\r\n",
                b"",
            ),
            (
                "invalid-utf8",
                b"Content-Length: 7\r\n",
                b"token=\xff",
            ),
            (
                "invalid-percent-encoded-utf8",
                b"Content-Length: 9\r\n",
                b"token=%FF",
            ),
            (
                "excess-fields",
                f"Content-Length: {len(excess_fields)}\r\n".encode(),
                excess_fields,
            ),
            (
                "oversized-value",
                f"Content-Length: {len(oversized_value)}\r\n".encode(),
                oversized_value,
            ),
            (
                "incomplete",
                b"Content-Length: 32\r\n",
                b"token=x",
            ),
        )

        for name, content_length, body in cases:
            with self.subTest(name=name):
                response = self.raw_post(
                    content_length=content_length,
                    body=body,
                    keep_write_open=False,
                )
                self.assert_fixed_400(response)
                self.assert_health_works()

        combined_logs = "\n".join(self.logs)
        for canary in ("negative-sensitive-value", "field32"):
            self.assertNotIn(canary, combined_logs)

    def test_slow_incomplete_form_is_bounded_and_server_recovers(self):
        started = time.monotonic()
        response = self.raw_post(
            content_length=b"Content-Length: 32\r\n",
            body=b"token=x",
            keep_write_open=True,
        )
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 3.0)
        self.assert_fixed_400(response)
        self.assert_health_works()

    def raw_post(self, content_length, body, keep_write_open):
        connection = socket.create_connection(
            ("127.0.0.1", self.httpd.server_port),
            timeout=2,
        )
        connection.settimeout(2.5)
        request = (
            b"POST /introspect HTTP/1.0\r\n"
            b"Host: localhost\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            + content_length
            + b"\r\n"
            + body
        )
        try:
            connection.sendall(request)
            if not keep_write_open:
                connection.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                try:
                    chunk = connection.recv(4096)
                except TimeoutError:
                    return b""
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            connection.close()

    def assert_fixed_400(self, response):
        self.assertIn(b" 400 ", response.split(b"\r\n", 1)[0])
        self.assertIn(b'"error": "invalid_request"', response)
        self.assertIn(b'"error_description": "Request form is invalid"', response)
        self.assertNotIn(b"sensitive", response)

    def assert_health_works(self):
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.httpd.server_port,
            timeout=2,
        )
        try:
            connection.request("GET", "/health")
            response = connection.getresponse()
            body = response.read()
            self.assertEqual(200, response.status)
            self.assertEqual({"status": "ok"}, json.loads(body))
        finally:
            connection.close()

        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.httpd.server_port,
            timeout=2,
        )
        try:
            form = "token=valid-eligible%40local.test"
            connection.request(
                "POST",
                "/introspect",
                body=form,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response = connection.getresponse()
            body = response.read()
            self.assertEqual(200, response.status)
            self.assertTrue(json.loads(body)["active"])
        finally:
            connection.close()


class HttpResponse:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def json(self):
        return json.loads(self.body)


if __name__ == "__main__":
    unittest.main()
