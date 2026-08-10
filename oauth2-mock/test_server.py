import http.client
import io
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
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
PASSWD_SHAPE_CORPUS_PATH = SERVER_PATH.parent.parent.joinpath(
    "debug-dashboard",
    "dashboard-server",
    "testResources",
    "dovecot-gate0c",
    "passwd-shapes.txt",
)
SERVER_SPEC = importlib.util.spec_from_file_location("oauth2_mock_server", SERVER_PATH)
server = importlib.util.module_from_spec(SERVER_SPEC)
SERVER_SPEC.loader.exec_module(server)


VALID_PASSWORD_FIELD = "{PLAIN}secret"


def eligibility_record(address, password_field=VALID_PASSWORD_FIELD):
    return f"{address}:{password_field}::::::"


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
            f"{eligibility_record('eligible@local.test')}\n"
            f"{eligibility_record('second.user+tag@local.test')}\n"
        )
        reader = server.EligibilityReader(self.authority)

        self.assertTrue(reader.is_eligible("eligible@local.test"))
        self.assertTrue(reader.is_eligible("second.user+tag@local.test"))
        self.assertFalse(reader.is_eligible("absent@local.test"))
        self.assertFalse(reader.is_eligible("ELIGIBLE@local.test"))

    def test_malformed_authority_fails_closed_for_every_identity(self):
        malformed_authorities = (
            f"{eligibility_record('eligible@local.test')}\r\n",
            f"{eligibility_record('ELIGIBLE@local.test')}\n",
            f"{eligibility_record('eligible@local.test', '{PLAIN}')}\n",
        )

        for index, contents in enumerate(malformed_authorities):
            with self.subTest(index=index):
                self.write_authority(contents)
                reader = server.EligibilityReader(self.authority)
                self.assertFalse(reader.is_eligible("eligible@local.test"))

    def test_duplicate_addresses_fail_closed(self):
        self.write_authority(
            f"{eligibility_record('eligible@local.test')}\n"
            f"{eligibility_record('eligible@local.test', '{PLAIN}other')}\n",
        )

        reader = server.EligibilityReader(self.authority)

        self.assertEqual(
            server.EligibilityResult.UNAVAILABLE,
            reader.eligibility("eligible@local.test"),
        )

    def test_argon2id_two_field_non_eight_field_and_final_field_are_rejected(self):
        invalid_records = (
            (
                "eligible@local.test:{ARGON2ID}$argon2id$v=19$"
                "m=65536,t=3,p=1$c2FsdA$ZGlnZXN0::::::\n"
            ),
            "eligible@local.test:{PLAIN}secret\n",
            "eligible@local.test:{PLAIN}secret:::::\n",
            "eligible@local.test:{PLAIN}secret::::::tail\n",
            "eligible@local.test:{PLAIN}secret:::::shell:\n",
        )

        for record in invalid_records:
            with self.subTest(record=record):
                self.write_authority(record)
                reader = server.EligibilityReader(self.authority)
                self.assertEqual(
                    server.EligibilityResult.UNAVAILABLE,
                    reader.eligibility("eligible@local.test"),
                )

    def test_shared_passwd_shape_corpus_matches_reader_grammar(self):
        for shape in self._read_passwd_shape_corpus():
            with self.subTest(case_id=shape["id"]):
                self.write_authority(f"{shape['record']}\n")
                reader = server.EligibilityReader(self.authority)
                expected = (
                    server.EligibilityResult.ELIGIBLE
                    if shape["accepted"]
                    else server.EligibilityResult.UNAVAILABLE
                )
                self.assertEqual(
                    expected,
                    reader.eligibility("eligible@local.test"),
                )

    def _read_passwd_shape_corpus(self):
        self.assertTrue(
            PASSWD_SHAPE_CORPUS_PATH.is_file(),
            "shared passwd-shape corpus is missing",
        )
        corpus_bytes = PASSWD_SHAPE_CORPUS_PATH.read_bytes()
        self.assertTrue(
            corpus_bytes
            and all(
                byte in (0x09, 0x0A) or 0x20 <= byte <= 0x7E
                for byte in corpus_bytes
            ),
            "passwd-shape corpus must contain only printable ASCII, tabs, and LF",
        )
        contents = corpus_bytes.decode("ascii")
        self.assertTrue(
            contents.endswith("\n"),
            "passwd-shape corpus must end with a newline",
        )
        cases = []
        seen_ids = set()
        for line_number, line in enumerate(
            contents.removesuffix("\n").split("\n"),
            start=1,
        ):
            if line.startswith("#"):
                continue
            self.assertTrue(
                line,
                f"invalid passwd-shape corpus blank row at line {line_number}",
            )
            fields = line.split("\t")
            self.assertEqual(
                5,
                len(fields),
                f"invalid passwd-shape corpus row at line {line_number}",
            )
            outcome, case_id, column_count_text, populated_text, template = fields
            self.assertIn(
                outcome,
                ("accept", "reject"),
                f"invalid passwd-shape outcome at line {line_number}",
            )
            self.assertRegex(
                case_id,
                r"\A[a-z0-9]+(?:-[a-z0-9]+)*\Z",
                f"invalid passwd-shape id at line {line_number}",
            )
            self.assertNotIn(
                case_id,
                seen_ids,
                f"duplicate passwd-shape id at line {line_number}",
            )
            seen_ids.add(case_id)
            self.assertRegex(
                column_count_text,
                r"\A[1-9][0-9]?\Z",
                f"invalid passwd-shape column count at line {line_number}",
            )
            column_count = int(column_count_text)
            self.assertTrue(
                2 <= column_count <= 16,
                f"passwd-shape column count is out of bounds at line {line_number}",
            )
            if populated_text == "<none>":
                populated_column = None
            else:
                self.assertRegex(
                    populated_text,
                    r"\A[2-7]\Z",
                    f"invalid populated userdb column at line {line_number}",
                )
                populated_column = int(populated_text)
            self.assertEqual(
                1,
                template.count("{{address}}"),
                f"invalid address placeholder at line {line_number}",
            )
            self.assertEqual(
                1,
                template.count("{{hash}}"),
                f"invalid hash placeholder at line {line_number}",
            )
            without_known_placeholders = template.replace(
                "{{address}}",
                "",
            ).replace(
                "{{hash}}",
                "",
            )
            self.assertNotIn(
                "{{",
                without_known_placeholders,
                f"unknown passwd-shape placeholder at line {line_number}",
            )
            self.assertNotIn(
                "}}",
                without_known_placeholders,
                f"unknown passwd-shape placeholder at line {line_number}",
            )
            columns = template.split(":")
            self.assertEqual(
                column_count,
                len(columns),
                f"passwd-shape metadata does not match record {case_id}",
            )
            self.assertEqual(
                ("{{address}}", "{{hash}}"),
                tuple(columns[:2]),
                f"passwd-shape case {case_id} has invalid credential columns",
            )
            populated_columns = [
                index
                for index, field in enumerate(columns[2:], start=2)
                if field
            ]
            if populated_column is None:
                self.assertEqual(
                    [],
                    populated_columns,
                    f"passwd-shape populated metadata does not match {case_id}",
                )
            else:
                self.assertEqual(
                    8,
                    column_count,
                    f"populated userdb metadata requires eight columns for {case_id}",
                )
                self.assertEqual(
                    [populated_column],
                    populated_columns,
                    f"passwd-shape populated metadata does not match {case_id}",
                )
            cases.append(
                {
                    "accepted": outcome == "accept",
                    "id": case_id,
                    "column_count": column_count,
                    "populated_column": populated_column,
                    "record": template.replace(
                        "{{address}}",
                        "eligible@local.test",
                    ).replace(
                        "{{hash}}",
                        VALID_PASSWORD_FIELD,
                    ),
                },
            )
        self.assertEqual(
            len(cases),
            len({shape["record"] for shape in cases}),
            "passwd-shape corpus contains duplicate effective records",
        )
        self._assert_passwd_shape_coverage(cases)
        return cases

    def _assert_passwd_shape_coverage(self, cases):
        accepted = [shape for shape in cases if shape["accepted"]]
        self.assertEqual(1, len(accepted))
        self.assertEqual(8, accepted[0]["column_count"])
        self.assertIsNone(accepted[0]["populated_column"])
        canonical_column_count = accepted[0]["column_count"]

        rejected = [shape for shape in cases if not shape["accepted"]]
        self.assertTrue(
            any(shape["column_count"] == 2 for shape in rejected),
            "passwd-shape corpus must cover the legacy credential-only record",
        )
        self.assertTrue(
            any(
                shape["column_count"] == canonical_column_count - 1
                for shape in rejected
            ),
            "passwd-shape corpus must cover adjacent delimiter underflow",
        )
        self.assertTrue(
            any(
                shape["column_count"] == canonical_column_count + 1
                for shape in rejected
            ),
            "passwd-shape corpus must cover adjacent delimiter overflow",
        )
        rejected_canonical_width = [
            shape
            for shape in rejected
            if shape["column_count"] == canonical_column_count
        ]
        userdb_columns = set(range(2, canonical_column_count))
        self.assertEqual(len(userdb_columns), len(rejected_canonical_width))
        self.assertEqual(
            userdb_columns,
            {
                shape["populated_column"]
                for shape in rejected_canonical_width
                if shape["populated_column"] is not None
            },
            "passwd-shape corpus must cover each populated userdb column once",
        )

    def test_protected_authority_identities_and_subaddresses_fail_closed(self):
        protected_addresses = (
            "dashboard-management@local.test",
            "dashboard-management+tag@local.test",
            "dashboard-operator-a@local.test",
            "dashboard-operator-a+tag@local.test",
            "dashboard-operator-b@local.test",
            "dashboard-operator-b+tag@local.test",
        )

        for protected_address in protected_addresses:
            with self.subTest(protected_address=protected_address):
                self.write_authority(
                    f"{eligibility_record('eligible@local.test')}\n"
                    f"{eligibility_record(protected_address)}\n",
                )
                reader = server.EligibilityReader(self.authority)

                self.assertEqual(
                    server.EligibilityResult.UNAVAILABLE,
                    reader.eligibility("eligible@local.test"),
                )
                self.assertFalse(
                    server.EligibilityReader._is_canonical_address(
                        protected_address,
                    ),
                )

    def test_symlink_authority_fails_closed(self):
        real_authority = self.root / "real-users"
        real_authority.write_text(
            f"{eligibility_record('eligible@local.test')}\n",
            encoding="utf-8",
        )
        os.chmod(real_authority, 0o600)
        self.authority.symlink_to(real_authority)

        reader = server.EligibilityReader(self.authority)

        self.assertFalse(reader.is_eligible("eligible@local.test"))

    def test_atomic_replacement_is_visible_to_the_long_running_reader(self):
        self.write_authority(f"{eligibility_record('eligible@local.test')}\n")
        reader = server.EligibilityReader(self.authority)
        self.assertTrue(reader.is_eligible("eligible@local.test"))

        replacement = self.root / "users.replacement"
        replacement.write_text(
            f"{eligibility_record('replacement@local.test')}\n",
            encoding="utf-8",
        )
        os.chmod(replacement, 0o600)
        os.replace(replacement, self.authority)

        self.assertFalse(reader.is_eligible("eligible@local.test"))
        self.assertTrue(reader.is_eligible("replacement@local.test"))

    def test_explicit_result_distinguishes_absence_from_unavailable_authority(self):
        self.write_authority(f"{eligibility_record('eligible@local.test')}\n")
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
        self.write_authority(f"{eligibility_record('eligible@local.test')}\n")
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

        self.write_authority(f"{eligibility_record('eligible@local.test')}\n")
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
                    f"{eligibility_record('eligible@local.test')}\n",
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
                    f"{eligibility_record('eligible@local.test')}\n",
                )
                reader = server.EligibilityReader(self.authority)
                self.assertFalse(reader.is_eligible("eligible@local.test"))

    def write_authority(self, contents):
        self.authority.unlink(missing_ok=True)
        self.authority.write_text(contents, encoding="utf-8")
        os.chmod(self.authority, 0o600)


class SocketMapLookupTest(unittest.TestCase):
    def setUp(self):
        self.reader = MutableEligibilityReader(
            "eligible@local.test",
            "ordinary@local.test",
            "ordinary+tag@local.test",
            "dashboard-management@local.test",
            "dashboard-management+tag@local.test",
            "dashboard-operator-a@local.test",
            "dashboard-operator-a+tag@local.test",
            "dashboard-operator-b@local.test",
            "dashboard-operator-b+tag@local.test",
        )

    def lookup(self, payload):
        self.assertTrue(
            hasattr(server, "SocketMapLookup"),
            "Task 4 socketmap lookup is not implemented",
        )
        return server.SocketMapLookup(self.reader).lookup(payload)

    def test_exact_canonical_eligible_local_recipient_returns_nonempty_ok(self):
        response = self.lookup(b"eligible eligible@local.test")

        self.assertTrue(response.startswith(b"OK "))
        self.assertNotEqual(b"OK ", response)

    def test_absent_malformed_offdomain_and_protected_recipients_are_not_found(self):
        recipients = (
            "absent@local.test",
            "ELIGIBLE@local.test",
            "eligible@other.test",
            "eligible@sub.local.test",
            "eligible",
            "../eligible@local.test",
            "dashboard-management@local.test",
            "dashboard-management+tag@local.test",
            "dashboard-operator-a@local.test",
            "dashboard-operator-a+tag@local.test",
            "dashboard-operator-b@local.test",
            "dashboard-operator-b+tag@local.test",
        )

        for recipient in recipients:
            with self.subTest(recipient=recipient):
                self.assertEqual(
                    b"NOTFOUND ",
                    self.lookup(f"eligible {recipient}".encode("ascii")),
                )

    def test_ordinary_subaddresses_require_the_exact_full_address(self):
        self.assertEqual(
            b"OK 1",
            self.lookup(b"eligible ordinary+tag@local.test"),
        )
        self.assertEqual(
            b"NOTFOUND ",
            self.lookup(b"eligible ordinary+absent@local.test"),
        )

    def test_wrong_map_or_missing_separator_is_a_permanent_protocol_error(self):
        cases = (
            (b"other eligible@local.test", b"PERM unsupported map"),
            (b"eligible", b"PERM malformed request"),
            (b" eligible@local.test", b"PERM malformed request"),
        )

        for payload, expected in cases:
            with self.subTest(payload=payload):
                self.assertEqual(expected, self.lookup(payload))

    def test_invalid_keys_after_the_exact_map_are_not_found(self):
        for payload in (
            b"eligible ",
            b"eligible eligible@local.test extra",
            b"eligible \xff",
        ):
            with self.subTest(payload=payload):
                self.assertEqual(b"NOTFOUND ", self.lookup(payload))

    def test_unavailable_authority_is_temporary_but_invalid_target_is_not_found(self):
        class UnavailableReader:
            def eligibility(self, username):
                return server.EligibilityResult.UNAVAILABLE

        self.assertTrue(
            hasattr(server, "SocketMapLookup"),
            "Task 4 socketmap lookup is not implemented",
        )
        lookup = server.SocketMapLookup(UnavailableReader())

        self.assertEqual(
            b"TEMP eligibility authority unavailable",
            lookup.lookup(b"eligible eligible@local.test"),
        )
        self.assertEqual(
            b"NOTFOUND ",
            lookup.lookup(b"eligible ELIGIBLE@local.test"),
        )

    def test_each_lookup_reads_current_authority_after_deletion_and_update(self):
        with tempfile.TemporaryDirectory() as temporary:
            authority = Path(temporary) / "users"

            def write(contents):
                authority.write_text(contents, encoding="utf-8")
                os.chmod(authority, 0o600)

            write(f"{eligibility_record('eligible@local.test')}\n")
            self.assertTrue(
                hasattr(server, "SocketMapLookup"),
                "Task 4 socketmap lookup is not implemented",
            )
            lookup = server.SocketMapLookup(server.EligibilityReader(authority))

            self.assertTrue(
                lookup.lookup(b"eligible eligible@local.test").startswith(b"OK "),
            )
            write("")
            self.assertEqual(
                b"NOTFOUND ",
                lookup.lookup(b"eligible eligible@local.test"),
            )
            write(f"{eligibility_record('replacement@local.test')}\n")
            self.assertEqual(
                b"NOTFOUND ",
                lookup.lookup(b"eligible eligible@local.test"),
            )
            self.assertTrue(
                lookup.lookup(b"eligible replacement@local.test").startswith(b"OK "),
            )


class ActualSocketMapServerTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(
            hasattr(server, "SocketMapServer"),
            "Task 4 socketmap server is not implemented",
        )
        self.logs = []
        lookup = server.SocketMapLookup(
            MutableEligibilityReader("eligible@local.test"),
        )
        self.socketmap = server.SocketMapServer(
            ("127.0.0.1", 0),
            lookup,
            log_message=self.logs.append,
            request_timeout_seconds=1.0,
        )
        self.thread = threading.Thread(
            target=self.socketmap.serve_forever,
            name="socketmap-actual-test",
            daemon=True,
        )
        self.thread.start()

    def tearDown(self):
        socketmap = getattr(self, "socketmap", None)
        if socketmap is None:
            return
        socketmap.shutdown()
        socketmap.server_close()
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive(), "socketmap test server did not stop")

    def test_fragmented_request_returns_ok_and_next_connection_succeeds(self):
        request = self.netstring(b"eligible eligible@local.test")

        response = self.exchange(tuple(bytes((byte,)) for byte in request))

        self.assertEqual(self.netstring(b"OK 1"), response)
        self.assertEqual(
            self.netstring(b"NOTFOUND "),
            self.exchange((self.netstring(b"eligible absent@local.test"),)),
        )

    def test_reused_connection_accepts_multiple_sequential_requests(self):
        connection = socket.create_connection(
            ("127.0.0.1", self.socketmap.server_address[1]),
            timeout=2,
        )
        connection.settimeout(2)
        try:
            connection.sendall(
                self.netstring(b"eligible eligible@local.test")
                + self.netstring(b"eligible absent@local.test"),
            )
            connection.shutdown(socket.SHUT_WR)
            response = self.receive_all(connection)
        finally:
            connection.close()

        self.assertEqual(
            self.netstring(b"OK 1") + self.netstring(b"NOTFOUND "),
            response,
        )

    def test_idle_after_success_closes_without_an_unsolicited_response(self):
        expected = self.netstring(b"OK 1")
        connection = socket.create_connection(
            ("127.0.0.1", self.socketmap.server_address[1]),
            timeout=2,
        )
        connection.settimeout(2)
        try:
            connection.sendall(
                self.netstring(b"eligible eligible@local.test"),
            )
            received = bytearray()
            while len(received) < len(expected):
                received.extend(connection.recv(len(expected) - len(received)))
            trailing = self.receive_all(connection)
        finally:
            connection.close()

        self.assertEqual(expected, bytes(received))
        self.assertEqual(
            b"",
            trailing,
            "an idle keep-alive produced an unsolicited socketmap reply",
        )

    def test_stalled_connection_does_not_serialize_another_lookup(self):
        original_timeout = self.socketmap.request_timeout_seconds
        self.socketmap.request_timeout_seconds = 3.0
        stalled = socket.create_connection(
            ("127.0.0.1", self.socketmap.server_address[1]),
            timeout=2,
        )
        stalled.settimeout(2)
        stalled.sendall(b"40:eligible eligible@local")
        completed = threading.Event()
        result = []

        def run_fast_lookup():
            result.append(
                self.exchange(
                    (self.netstring(b"eligible eligible@local.test"),),
                ),
            )
            completed.set()

        fast = threading.Thread(target=run_fast_lookup, daemon=True)
        fast.start()
        try:
            self.assertTrue(
                completed.wait(1.5),
                "a stalled client serialized an independent lookup",
            )
        finally:
            stalled.close()
            self.socketmap.request_timeout_seconds = original_timeout
            fast.join(timeout=2)

        self.assertFalse(fast.is_alive())
        self.assertEqual([self.netstring(b"OK 1")], result)

    def test_fast_stream_is_capped_and_capacity_recovers(self):
        self.assertTrue(
            hasattr(server, "MAX_SOCKETMAP_REQUESTS_PER_CONNECTION"),
            "Task 4 per-connection request cap is not implemented",
        )
        maximum = server.MAX_SOCKETMAP_REQUESTS_PER_CONNECTION
        request = self.netstring(b"eligible eligible@local.test")
        expected = self.netstring(b"OK 1")
        connection = socket.create_connection(
            ("127.0.0.1", self.socketmap.server_address[1]),
            timeout=2,
        )
        connection.settimeout(2)
        try:
            responses = []
            for _ in range(maximum):
                connection.sendall(request)
                response = bytearray()
                while len(response) < len(expected):
                    response.extend(
                        connection.recv(len(expected) - len(response)),
                    )
                responses.append(bytes(response))
            try:
                connection.sendall(request)
                trailing = self.receive_all(connection)
            except OSError:
                trailing = b""
        finally:
            connection.close()

        self.assertEqual([expected] * maximum, responses)
        self.assertEqual(b"", trailing)
        self.assertEqual(
            expected,
            self.exchange((request,)),
            "the capped connection leaked its concurrency slot",
        )

    def test_saturation_never_sends_an_unsolicited_reply_and_then_recovers(self):
        self.assertTrue(
            hasattr(server, "MAX_SOCKETMAP_CONNECTIONS"),
            "Task 4 connection bound is not implemented",
        )
        held = []
        original_timeout = self.socketmap.request_timeout_seconds
        self.socketmap.request_timeout_seconds = 10.0
        try:
            for _ in range(server.MAX_SOCKETMAP_CONNECTIONS):
                connection = socket.create_connection(
                    ("127.0.0.1", self.socketmap.server_address[1]),
                    timeout=2,
                )
                connection.settimeout(2)
                connection.sendall(b"40:eligible eligible@local")
                held.append(connection)

            deadline = time.monotonic() + 2
            while (
                self.socketmap.active_connection_count
                < server.MAX_SOCKETMAP_CONNECTIONS
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            self.assertEqual(
                server.MAX_SOCKETMAP_CONNECTIONS,
                self.socketmap.active_connection_count,
            )
            overflow = socket.create_connection(
                ("127.0.0.1", self.socketmap.server_address[1]),
                timeout=2,
            )
            overflow.settimeout(2)
            try:
                unsolicited = overflow.recv(4096)
            finally:
                overflow.close()

            self.assertEqual(
                b"",
                unsolicited,
                "a saturated server replied before receiving a request",
            )
        finally:
            for connection in held:
                connection.close()
            self.socketmap.request_timeout_seconds = original_timeout

        expected = self.netstring(b"OK 1")
        deadline = time.monotonic() + 2
        while (
            self.socketmap.active_connection_count
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        self.assertEqual(0, self.socketmap.active_connection_count)
        response = b""
        while time.monotonic() < deadline:
            try:
                response = self.exchange(
                    (self.netstring(b"eligible eligible@local.test"),),
                )
            except OSError:
                response = b""
            if response == expected:
                break
            time.sleep(0.02)
        self.assertEqual(expected, response)

    def test_length_syntax_bound_terminator_and_truncation_fail_then_recover(self):
        self.assertTrue(
            hasattr(server, "MAX_SOCKETMAP_REQUEST_BYTES"),
            "Task 4 socketmap request bound is not implemented",
        )
        maximum = server.MAX_SOCKETMAP_REQUEST_BYTES
        cases = (
            b":,",
            b"+1:x,",
            b"01:x,",
            f"{maximum + 1}:".encode("ascii"),
            b"3:abc;",
            b"20:eligible",
        )

        for request in cases:
            with self.subTest(request=request[:16]):
                response = self.exchange((request,))
                self.assertEqual(
                    self.netstring(b"PERM malformed request"),
                    response,
                )
                self.assertEqual(
                    self.netstring(b"OK 1"),
                    self.exchange(
                        (self.netstring(b"eligible eligible@local.test"),),
                    ),
                )

    def test_slow_truncated_request_times_out_without_blocking_recovery(self):
        connection = socket.create_connection(
            ("127.0.0.1", self.socketmap.server_address[1]),
            timeout=2,
        )
        connection.settimeout(2)
        started = time.monotonic()
        try:
            connection.sendall(b"40:eligible eligible@local")
            response = self.receive_all(connection)
        finally:
            connection.close()

        self.assertLess(time.monotonic() - started, 2.5)
        self.assertEqual(self.netstring(b"PERM malformed request"), response)
        self.assertEqual(
            self.netstring(b"OK 1"),
            self.exchange((self.netstring(b"eligible eligible@local.test"),)),
        )

    def test_malformed_payload_is_absent_from_response_and_logs(self):
        canary = b"socketmap-raw-payload-canary"
        response = self.exchange(
            (f"{len(canary)}:".encode("ascii") + canary + b";",),
        )

        self.assertEqual(self.netstring(b"PERM malformed request"), response)
        self.assertNotIn(canary, response)
        self.assertNotIn(canary.decode("ascii"), "\n".join(self.logs))

    def test_outcome_logs_are_bounded_labels_without_recipient_data(self):
        canary = "socketmap-outcome-canary@local.test"
        self.assertEqual(
            self.netstring(b"OK 1"),
            self.exchange(
                (self.netstring(b"eligible eligible@local.test"),),
            ),
        )
        self.assertEqual(
            self.netstring(b"NOTFOUND "),
            self.exchange(
                (self.netstring(f"eligible {canary}".encode("ascii")),),
            ),
        )
        self.assertEqual(
            self.netstring(b"PERM unsupported map"),
            self.exchange(
                (self.netstring(b"other eligible@local.test"),),
            ),
        )

        class UnavailableReader:
            def eligibility(self, username):
                return server.EligibilityResult.UNAVAILABLE

        self.socketmap.lookup = server.SocketMapLookup(UnavailableReader())
        self.assertEqual(
            self.netstring(b"TEMP eligibility authority unavailable"),
            self.exchange(
                (self.netstring(b"eligible eligible@local.test"),),
            ),
        )

        combined_logs = "\n".join(self.logs)
        for label in ("OK", "NOTFOUND", "TEMP", "protocol-error"):
            self.assertIn(f"Socketmap lookup outcome={label}", combined_logs)
        self.assertNotIn(canary, combined_logs)

    def exchange(self, fragments):
        connection = socket.create_connection(
            ("127.0.0.1", self.socketmap.server_address[1]),
            timeout=2,
        )
        connection.settimeout(2)
        try:
            for fragment in fragments:
                connection.sendall(fragment)
            try:
                connection.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            return self.receive_all(connection)
        finally:
            connection.close()

    @staticmethod
    def receive_all(connection):
        chunks = []
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)

    @staticmethod
    def netstring(payload):
        return str(len(payload)).encode("ascii") + b":" + payload + b","


class ServiceLifecycleTest(unittest.TestCase):
    def test_socketmap_bind_failure_prevents_http_server_construction(self):
        http_constructed = []

        def fail_socketmap(*args, **kwargs):
            raise OSError("simulated socketmap bind failure")

        def construct_http(*args, **kwargs):
            http_constructed.append(True)
            return object()

        self.assertTrue(
            hasattr(server, "build_servers"),
            "Task 4 service construction lifecycle is not implemented",
        )
        with self.assertRaisesRegex(OSError, "socketmap bind failure"):
            server.build_servers(
                http_server_factory=construct_http,
                socketmap_server_factory=fail_socketmap,
            )

        self.assertEqual([], http_constructed)

    def test_socketmap_stop_requested_before_serve_exits_without_shutdown(self):
        stop_requested = threading.Event()
        stop_requested.set()
        socketmap = server.SocketMapServer(
            ("127.0.0.1", 0),
            server.SocketMapLookup(
                MutableEligibilityReader(),
            ),
            log_message=lambda message: None,
        )
        failures = []

        def serve():
            try:
                socketmap.serve_until(stop_requested)
            except BaseException as exception:
                failures.append(exception)

        service_thread = threading.Thread(target=serve, daemon=True)
        try:
            service_thread.start()
            service_thread.join(timeout=2)
        finally:
            socketmap.server_close()

        self.assertFalse(
            service_thread.is_alive(),
            "a stop request racing ahead of serve left the socketmap blocked",
        )
        self.assertEqual([], failures)

    def test_socketmap_start_failure_stops_http_and_is_propagated(self):
        class FakeHttpServer:
            def __init__(self):
                self.closed = False

            def serve_until(self, peer_stopped):
                if not peer_stopped.wait(1):
                    raise AssertionError("socketmap failure was not supervised")

            def server_close(self):
                self.closed = True

        class FailingSocketMapServer:
            def __init__(self):
                self.closed = False

            def serve_until(self, stop_requested):
                raise RuntimeError("simulated socketmap start failure")

            def shutdown(self):
                raise AssertionError("an already-stopped socketmap was shut down")

            def server_close(self):
                self.closed = True

        http = FakeHttpServer()
        socketmap = FailingSocketMapServer()
        self.assertTrue(
            hasattr(server, "serve_services"),
            "Task 4 service runtime lifecycle is not implemented",
        )

        with self.assertRaisesRegex(RuntimeError, "socketmap start failure"):
            server.serve_services(http, socketmap)

        self.assertTrue(http.closed)
        self.assertTrue(socketmap.closed)

    def test_http_failure_stops_socketmap_and_is_propagated(self):
        class FailingHttpServer:
            def __init__(self, socketmap):
                self.socketmap = socketmap
                self.closed = False

            def serve_until(self, peer_stopped):
                if not self.socketmap.started.wait(1):
                    raise AssertionError("socketmap did not start")
                raise RuntimeError("simulated HTTP server failure")

            def server_close(self):
                self.closed = True

        class RunningSocketMapServer:
            def __init__(self):
                self.started = threading.Event()
                self.stopped = threading.Event()
                self.exited = threading.Event()
                self.closed = False

            def serve_until(self, stop_requested):
                self.started.set()
                stop_requested.wait(2)
                self.exited.set()

            def shutdown(self):
                raise AssertionError("blocking shutdown must not be called")

            def server_close(self):
                self.closed = True

        socketmap = RunningSocketMapServer()
        http = FailingHttpServer(socketmap)

        with self.assertRaisesRegex(RuntimeError, "HTTP server failure"):
            server.serve_services(http, socketmap)

        self.assertTrue(socketmap.exited.is_set())
        self.assertTrue(socketmap.closed)
        self.assertTrue(http.closed)

    def test_unresponsive_socketmap_shutdown_has_a_bounded_join(self):
        class FailingHttpServer:
            def __init__(self, socketmap):
                self.socketmap = socketmap
                self.closed = False

            def serve_until(self, peer_stopped):
                if not self.socketmap.started.wait(1):
                    raise AssertionError("socketmap did not start")
                raise RuntimeError("simulated HTTP server failure")

            def server_close(self):
                self.closed = True

        class UnresponsiveSocketMapServer:
            def __init__(self):
                self.started = threading.Event()
                self.release = threading.Event()
                self.shutdown_called = threading.Event()
                self.closed = False

            def serve_until(self, stop_requested):
                self.started.set()
                self.release.wait(3)

            def shutdown(self):
                self.shutdown_called.set()
                self.release.wait(3)

            def server_close(self):
                self.closed = True

        socketmap = UnresponsiveSocketMapServer()
        http = FailingHttpServer(socketmap)
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(RuntimeError, "did not stop"):
                server.serve_services(http, socketmap)
        finally:
            socketmap.release.set()

        self.assertLess(time.monotonic() - started, 2.5)
        self.assertFalse(
            socketmap.shutdown_called.is_set(),
            "the supervisor called a potentially blocking shutdown method",
        )
        self.assertTrue(socketmap.closed)
        self.assertTrue(http.closed)

    def test_socketmap_failure_is_supervised_while_http_handler_is_blocked(self):
        handler_started = threading.Event()
        release_handler = threading.Event()

        class BlockingHandler(server.BaseHTTPRequestHandler):
            def do_GET(self):
                handler_started.set()
                release_handler.wait(3)
                self.send_response(200)
                self.end_headers()

            def log_message(self, format_, *args):
                return None

        class FailingSocketMapServer:
            def __init__(self):
                self.closed = False

            def serve_until(self, stop_requested):
                if not handler_started.wait(2):
                    raise AssertionError("HTTP handler did not start")
                raise RuntimeError("socketmap failed during blocked HTTP")

            def shutdown(self):
                raise AssertionError("blocking shutdown must not be called")

            def server_close(self):
                self.closed = True

        http = server.SupervisedHTTPServer(
            ("127.0.0.1", 0),
            BlockingHandler,
        )
        socketmap = FailingSocketMapServer()
        failures = []
        finished = threading.Event()

        def serve():
            try:
                server.serve_services(http, socketmap)
            except BaseException as exception:
                failures.append(exception)
            finally:
                finished.set()

        service_thread = threading.Thread(target=serve, daemon=True)
        service_thread.start()
        client = socket.create_connection(http.server_address, timeout=2)
        client.settimeout(2)
        try:
            client.sendall(
                b"GET /blocked HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Connection: close\r\n\r\n",
            )
            self.assertTrue(handler_started.wait(1))
            self.assertTrue(
                finished.wait(2),
                "blocked HTTP handler prevented socketmap failure supervision",
            )
        finally:
            release_handler.set()
            client.close()
            service_thread.join(timeout=2)

        self.assertFalse(service_thread.is_alive())
        self.assertEqual(1, len(failures))
        self.assertIsInstance(failures[0], RuntimeError)
        self.assertIn("failed during blocked HTTP", str(failures[0]))
        self.assertTrue(socketmap.closed)


class SupervisedHTTPServerCapacityTest(unittest.TestCase):
    def test_blocked_handlers_are_capped_overflow_closes_and_capacity_recovers(self):
        self.assertTrue(
            hasattr(server, "MAX_HTTP_CONNECTIONS"),
            "threaded HTTP handler concurrency is not bounded",
        )
        maximum = server.MAX_HTTP_CONNECTIONS
        release_handlers = threading.Event()
        peer_stopped = threading.Event()
        handler_count_lock = threading.Lock()
        handler_count = []

        class BlockingHandler(server.BaseHTTPRequestHandler):
            def do_GET(self):
                with handler_count_lock:
                    handler_count.append(self.path)
                if self.path == "/blocked":
                    release_handlers.wait(5)
                try:
                    self.send_response(200)
                    self.end_headers()
                except OSError:
                    pass

            def log_message(self, format_, *args):
                return None

        httpd = server.SupervisedHTTPServer(
            ("127.0.0.1", 0),
            BlockingHandler,
        )
        failures = []

        def serve():
            try:
                httpd.serve_until(peer_stopped)
            except server._PeerServerStopped:
                pass
            except BaseException as exception:
                failures.append(exception)

        service_thread = threading.Thread(target=serve, daemon=True)
        service_thread.start()
        held = []
        try:
            for _ in range(maximum):
                connection = socket.create_connection(
                    httpd.server_address,
                    timeout=2,
                )
                connection.settimeout(2)
                connection.sendall(
                    b"GET /blocked HTTP/1.1\r\n"
                    b"Host: localhost\r\n"
                    b"Connection: close\r\n\r\n",
                )
                held.append(connection)

            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                with handler_count_lock:
                    started_handlers = len(handler_count)
                if (
                    httpd.active_connection_count == maximum
                    and started_handlers == maximum
                ):
                    break
                time.sleep(0.01)
            self.assertEqual(maximum, httpd.active_connection_count)
            self.assertEqual(maximum, started_handlers)

            overflow = socket.create_connection(
                httpd.server_address,
                timeout=2,
            )
            overflow.settimeout(2)
            try:
                try:
                    overflow.sendall(
                        b"GET /overflow-canary HTTP/1.1\r\n"
                        b"Host: localhost\r\n"
                        b"Connection: close\r\n\r\n",
                    )
                    overflow_response = overflow.recv(4096)
                except OSError:
                    overflow_response = b""
            finally:
                overflow.close()

            self.assertEqual(
                b"",
                overflow_response,
                "HTTP saturation returned or reflected request data",
            )
            with handler_count_lock:
                self.assertEqual(maximum, len(handler_count))
                self.assertNotIn("/overflow-canary", handler_count)

            release_handlers.set()
            for connection in held:
                connection.close()
            held.clear()

            deadline = time.monotonic() + 2
            while (
                httpd.active_connection_count
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            self.assertEqual(0, httpd.active_connection_count)

            recovered = socket.create_connection(
                httpd.server_address,
                timeout=2,
            )
            recovered.settimeout(2)
            try:
                recovered.sendall(
                    b"GET /health HTTP/1.1\r\n"
                    b"Host: localhost\r\n"
                    b"Connection: close\r\n\r\n",
                )
                response = bytearray()
                while True:
                    chunk = recovered.recv(4096)
                    if not chunk:
                        break
                    response.extend(chunk)
            finally:
                recovered.close()

            self.assertIn(b" 200 ", bytes(response).partition(b"\r\n")[0])
            with handler_count_lock:
                self.assertEqual(maximum + 1, len(handler_count))
                self.assertEqual("/health", handler_count[-1])
        finally:
            release_handlers.set()
            for connection in held:
                connection.close()
            peer_stopped.set()
            service_thread.join(timeout=2)
            httpd.server_close()

        self.assertFalse(service_thread.is_alive())
        self.assertEqual([], failures)

    def test_delay_knob_has_a_finite_upper_bound(self):
        self.assertTrue(
            hasattr(server, "MAX_TEST_DELAY_SECONDS"),
            "the mock HTTP delay knob has no finite upper bound",
        )
        cases = (
            ("1000000000", (server.MAX_TEST_DELAY_SECONDS,)),
            ("inf", (server.MAX_TEST_DELAY_SECONDS,)),
            ("nan", ()),
            ("-1", ()),
            ("not-a-number", ()),
        )

        for value, expected_sleep in cases:
            with self.subTest(value=value):
                handler = types.SimpleNamespace(
                    path=f"/health?delay={value}",
                )
                with mock.patch.object(server.time, "sleep") as sleep:
                    handled = server._apply_test_knobs(handler)

                self.assertFalse(handled)
                if expected_sleep:
                    sleep.assert_called_once_with(*expected_sleep)
                else:
                    sleep.assert_not_called()


class OAuthComposeTest(unittest.TestCase):
    def test_oauth_mounts_the_shared_config_directory_read_only(self):
        self.assertEqual(
            Path("/etc/mail-sandbox-config/users"),
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
            "- ./config:/etc/mail-sandbox-config:ro",
            service,
        )
        self.assertNotIn(".runtime/dovecot", service)
        self.assertNotIn(".runtime/secrets", service)
        self.assertNotIn(".runtime/dovecot-operator", service)
        self.assertNotIn("/etc/mail-sandbox-config/users:", service)

    def test_socketmap_is_ready_internally_and_never_published_to_host(self):
        compose = SERVER_PATH.parent.parent.joinpath("docker-compose.yml").read_text(
            encoding="utf-8",
        )
        lines = compose.splitlines()
        oauth_start = lines.index("  oauth2-mock:")
        oauth_end = lines.index("  stalwart:")
        oauth = "\n".join(lines[oauth_start:oauth_end])
        postfix_start = lines.index("  postfix:")
        postfix_end = lines.index("  oauth2-mock:")
        postfix = "\n".join(lines[postfix_start:postfix_end])

        self.assertIn("10001", oauth)
        self.assertNotRegex(
            oauth,
            r'(?m)^\s*-\s+"[^"]*10001[^"]*"\s*(?:#.*)?$',
        )
        self.assertIn("socket.create_connection", oauth)
        self.assertIn("sendall", oauth)
        self.assertIn("NOTFOUND", oauth)
        self.assertIn("condition: service_healthy", postfix)
        self.assertIn("oauth2-mock:", postfix)
        self.assertIn("dovecot:", postfix)

    def test_resolved_compose_model_enforces_socketmap_boundary(self):
        repository = SERVER_PATH.parent.parent
        result = subprocess.run(
            ["docker", "compose", "config", "--format", "json"],
            cwd=repository,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(
            0,
            result.returncode,
            "docker compose config --format json failed",
        )
        model = json.loads(result.stdout)
        services = model["services"]

        for service_name, service in services.items():
            for publication in service.get("ports", []):
                with self.subTest(
                    service=service_name,
                    publication=publication,
                ):
                    self.assertNotEqual(10001, int(publication["target"]))
                    self.assertNotEqual(
                        10001,
                        int(publication["published"]),
                    )

        postfix_dependencies = services["postfix"]["depends_on"]
        for dependency in ("dovecot", "oauth2-mock"):
            self.assertEqual(
                "service_healthy",
                postfix_dependencies[dependency]["condition"],
            )

        health_test = services["oauth2-mock"]["healthcheck"]["test"]
        self.assertEqual(["CMD", "python", "-c"], health_test[:3])
        health_script = health_test[3]
        self.assertIn("http://localhost:8080/health", health_script)
        self.assertIn(
            "socket.create_connection(('127.0.0.1', 10001), 1)",
            health_script,
        )
        self.assertIn("sendall", health_script)
        self.assertIn("NOTFOUND", health_script)


class PostfixSocketMapConfigTest(unittest.TestCase):
    def setUp(self):
        self.repository = SERVER_PATH.parent.parent
        self.main_cf = self.repository.joinpath("postfix/main.cf").read_text(
            encoding="utf-8",
        )
        self.entrypoint = self.repository.joinpath("postfix/entrypoint.sh").read_text(
            encoding="utf-8",
        )

    def test_recipient_boundary_uses_exact_socketmap_and_rejects_unlisted(self):
        assignments = {}
        for name in (
            "local_recipient_maps",
            "smtpd_reject_unlisted_recipient",
        ):
            assignments[name] = [
                line
                for line in self.main_cf.splitlines()
                if line.partition("=")[0].strip() == name
            ]

        self.assertEqual(
            [
                "local_recipient_maps = "
                "socketmap:inet:oauth2-mock:10001:eligible"
            ],
            assignments["local_recipient_maps"],
        )
        self.assertEqual(
            ["smtpd_reject_unlisted_recipient = yes"],
            assignments["smtpd_reject_unlisted_recipient"],
        )
        self.assertIn(
            "smtpd_relay_restrictions = reject_unauth_destination\n",
            self.main_cf,
        )
        self.assertNotIn("local_recipient_maps =\n", self.main_cf)
        self.assertNotIn("smtpd_reject_unlisted_recipient = no", self.main_cf)

    def test_entrypoint_waits_boundedly_for_socketmap_and_dovecot(self):
        self.assertIn("MAX_WAIT_ATTEMPTS=60", self.entrypoint)
        self.assertIn("nc -z -w 1 \"$host\" \"$port\"", self.entrypoint)
        self.assertIn(
            "wait_for_service oauth2-mock 10001 \"OAuth socketmap\"",
            self.entrypoint,
        )
        self.assertIn(
            "wait_for_service dovecot 24 \"Dovecot LMTP\"",
            self.entrypoint,
        )
        self.assertNotIn("until nc -z", self.entrypoint)


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
