import io
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import types
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlencode, urlparse


SERVER_PATH = Path(__file__).with_name("server.py")
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

    def is_eligible(self, username):
        return username in self.eligible


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
            def is_eligible(self, username):
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
        self.assertEqual(400, refresh_exchange.status)
        self.assertEqual("invalid_grant", refresh_exchange.json()["error"])
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


class HttpResponse:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def json(self):
        return json.loads(self.body)


if __name__ == "__main__":
    unittest.main()
