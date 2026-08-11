from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "stalwart_v016_registry.py"
ABSENT = object()


def load_module():
    spec = importlib.util.spec_from_file_location(
        "stalwart_v016_registry_under_test",
        SCRIPT_PATH,
    )
    if spec is None or spec.loader is None:
        raise AssertionError("unable to load registry transport module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(
        self,
        payload: bytes,
        *,
        status: int = 200,
        headers: tuple[tuple[str, str], ...] = (
            ("Content-Type", "application/json"),
        ),
        close_error: BaseException | None = None,
    ) -> None:
        self.status = status
        self._payload = payload
        self._headers = headers
        self._close_error = close_error
        self.closed = False

    def getheaders(self) -> list[tuple[str, str]]:
        return list(self._headers)

    def read(self, amount: int | None = None) -> bytes:
        if amount is None:
            return self._payload
        return self._payload[:amount]

    def close(self) -> None:
        self.closed = True
        if self._close_error is not None:
            raise self._close_error


class FakeConnection:
    def __init__(
        self,
        response: FakeResponse | None,
        *,
        request_error: Exception | None = None,
        response_error: Exception | None = None,
        close_error: BaseException | None = None,
    ) -> None:
        self.response = response
        self.request_error = request_error
        self.response_error = response_error
        self.close_error = close_error
        self.requests: list[dict[str, object]] = []
        self.closed = False

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, object] | None = None,
    ) -> None:
        self.requests.append(
            {
                "method": method,
                "path": path,
                "body": body,
                "headers": {
                    key: bytes(value)
                    if isinstance(value, (bytes, bytearray, memoryview))
                    else value
                    for key, value in (headers or {}).items()
                },
            }
        )
        if self.request_error is not None:
            raise self.request_error

    def getresponse(self) -> FakeResponse:
        if self.response_error is not None:
            raise self.response_error
        if self.response is None:
            raise AssertionError("fake response is missing")
        return self.response

    def close(self) -> None:
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


class DynamicConnection(FakeConnection):
    def __init__(self, responder) -> None:
        super().__init__(None)
        self._responder = responder

    def getresponse(self) -> FakeResponse:
        if not self.requests:
            raise AssertionError("request must precede response")
        response = self._responder(self.requests[-1])
        if not isinstance(response, FakeResponse):
            raise AssertionError("responder must return FakeResponse")
        self.response = response
        return response


class ConnectionFactory:
    def __init__(self, connections: list[FakeConnection]) -> None:
        self.connections = connections
        self.calls: list[tuple[str, int, float]] = []

    def __call__(
        self,
        host: str,
        port: int,
        timeout: float,
    ) -> FakeConnection:
        self.calls.append((host, port, timeout))
        if not self.connections:
            raise AssertionError("unexpected HTTP connection")
        return self.connections.pop(0)


def strict_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def session_payload(
    *,
    username: str = "admin",
    account_id: str = "m1",
    api_url: str = "http://127.0.0.1:8443/jmap/",
) -> dict[str, object]:
    return {
        "accounts": {
            account_id: {
                "accountCapabilities": {
                    "urn:stalwart:jmap": {},
                },
                "isPersonal": True,
                "isReadOnly": False,
                "name": username,
            }
        },
        "apiUrl": api_url,
        "capabilities": {
            "urn:ietf:params:jmap:core": {},
            "urn:stalwart:jmap": {},
        },
        "downloadUrl": (
            "http://127.0.0.1:8443/jmap/download/"
            "{accountId}/{blobId}/{name}?accept={type}"
        ),
        "eventSourceUrl": (
            "http://127.0.0.1:8443/jmap/eventsource/"
            "?types={types}&closeafter={closeafter}&ping={ping}"
        ),
        "primaryAccounts": {
            "urn:ietf:params:jmap:principals": account_id,
            "urn:stalwart:jmap": account_id,
        },
        "state": "1",
        "uploadUrl": "http://127.0.0.1:8443/jmap/upload/{accountId}/",
        "username": username,
    }


def jmap_response(
    request: dict[str, object],
    payload: dict[str, object],
    *,
    response_name: str | None = None,
    response_call_id: str | None = None,
    extra_responses: list[object] | None = None,
    session_state: object = "1",
    created_ids: object = ABSENT,
) -> FakeResponse:
    body = json.loads(bytes(request["body"]).decode("utf-8"))
    method_call = body["methodCalls"][0]
    method = method_call[0]
    call_id = method_call[2]
    method_responses: list[object] = [
        [
            response_name if response_name is not None else method,
            payload,
            response_call_id if response_call_id is not None else call_id,
        ]
    ]
    method_responses.extend(extra_responses or [])
    response_body: dict[str, object] = {
        "methodResponses": method_responses,
    }
    if session_state is not ABSENT:
        response_body["sessionState"] = session_state
    if created_ids is not ABSENT:
        response_body["createdIds"] = created_ids
    return FakeResponse(strict_json_bytes(response_body))


def query_payload(
    *,
    account_id: str = "m1",
    ids: list[str] | None = None,
    position: int = 0,
    total: int = 0,
    query_state: str = "n",
) -> dict[str, object]:
    return {
        "accountId": account_id,
        "canCalculateChanges": True,
        "ids": ids or [],
        "position": position,
        "queryState": query_state,
        "total": total,
    }


def get_payload(
    *,
    account_id: str = "m1",
    values: list[dict[str, object]] | None = None,
    not_found: list[str] | None = None,
) -> dict[str, object]:
    return {
        "accountId": account_id,
        "list": values or [],
        "notFound": not_found or [],
        "state": "n",
    }


class CredentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_basic_credential_is_mutable_closeable_and_redacted(self) -> None:
        credential = self.module.BasicCredential(
            "admin",
            bytearray(b"top-secret"),
        )
        password_buffer = credential._password

        self.assertNotIn("admin", repr(credential))
        self.assertNotIn("top-secret", repr(credential))
        header = credential._authorization_header()
        self.assertEqual(
            bytes(header),
            b"Basic " + base64.b64encode(b"admin:top-secret"),
        )

        credential.close()

        self.assertTrue(credential.closed)
        self.assertEqual(set(password_buffer), {0})
        self.assertEqual(set(header), {0})
        with self.assertRaises(self.module.CredentialClosedError):
            credential._authorization_header()

    def test_bearer_credential_is_mutable_closeable_and_redacted(self) -> None:
        credential = self.module.BearerCredential(
            bytearray(b"API_0123456789abcdefghijklmnopqrstuvwxyz-_"),
        )
        token_buffer = credential._token

        self.assertNotIn("API_", repr(credential))
        header = credential._authorization_header()
        self.assertEqual(
            bytes(header),
            b"Bearer API_0123456789abcdefghijklmnopqrstuvwxyz-_",
        )

        credential.close()

        self.assertTrue(credential.closed)
        self.assertEqual(set(token_buffer), {0})
        self.assertEqual(set(header), {0})

    def test_bearer_credential_rejects_header_injection(self) -> None:
        with self.assertRaises(ValueError):
            self.module.BearerCredential(bytearray(b"secret\r\nX-Evil: yes"))

    def test_client_construction_failure_wipes_transferred_credential(self) -> None:
        class FloatSubclass(float):
            pass

        invalid_options = (
            {"expected_username": ""},
            {
                "expected_username": "admin",
                "expected_account_id": "invalid account",
            },
            {
                "expected_username": "admin",
                "timeout_seconds": 0,
            },
            {
                "expected_username": "admin",
                "timeout_seconds": True,
            },
            {
                "expected_username": "admin",
                "timeout_seconds": float("nan"),
            },
            {
                "expected_username": "admin",
                "timeout_seconds": float("inf"),
            },
            {
                "expected_username": "admin",
                "timeout_seconds": FloatSubclass(1),
            },
        )
        for options in invalid_options:
            with self.subTest(options=options):
                credential = self.module.BasicCredential(
                    "admin",
                    bytearray(b"unit-secret"),
                )
                password = credential._password

                with self.assertRaises(Exception):
                    self.module.RegistryClient(credential, **options)

                self.assertTrue(credential.closed)
                self.assertEqual(set(password), {0})


class DiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def client_for(
        self,
        response: FakeResponse,
        *,
        expected_username: str = "admin",
        expected_account_id: str | None = None,
    ):
        connection = FakeConnection(response)
        factory = ConnectionFactory([connection])
        patcher = mock.patch.object(
            self.module.http.client,
            "HTTPConnection",
            factory,
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        credential = self.module.BasicCredential("admin", bytearray(b"secret"))
        client = self.module.RegistryClient(
            credential,
            expected_username=expected_username,
            expected_account_id=expected_account_id,
            timeout_seconds=3.5,
        )
        self.addCleanup(client.close)
        return client, connection, factory

    def test_discovers_only_the_fixed_loopback_session_endpoint(self) -> None:
        client, connection, factory = self.client_for(
            FakeResponse(strict_json_bytes(session_payload()))
        )

        session = client.discover()

        self.assertEqual(session.username, "admin")
        self.assertEqual(session.account_id, "m1")
        self.assertEqual(session.api_path, "/jmap/")
        self.assertEqual(factory.calls, [("127.0.0.1", 8443, 3.5)])
        self.assertEqual(len(connection.requests), 1)
        request = connection.requests[0]
        self.assertEqual(request["method"], "GET")
        self.assertEqual(request["path"], "/.well-known/jmap")
        self.assertIsNone(request["body"])
        self.assertEqual(
            request["headers"],
            {
                "Accept": "application/json",
                "Authorization": (
                    b"Basic " + base64.b64encode(b"admin:secret")
                ),
            },
        )
        self.assertTrue(connection.closed)
        self.assertTrue(connection.response.closed)

    def test_rejects_session_identity_or_endpoint_mismatch(self) -> None:
        mutations = (
            {"username": "other"},
            {"apiUrl": "http://localhost:8443/jmap/"},
            {
                "capabilities": {
                    "urn:ietf:params:jmap:core": None,
                    "urn:stalwart:jmap": {},
                }
            },
            {
                "primaryAccounts": {
                    "urn:stalwart:jmap": "other",
                }
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                payload = session_payload()
                payload.update(mutation)
                client, _, _ = self.client_for(
                    FakeResponse(strict_json_bytes(payload))
                )
                with self.assertRaises(self.module.RegistryProtocolError):
                    client.discover()

    def test_rejects_primary_account_without_stalwart_capability(self) -> None:
        payload = session_payload()
        payload["accounts"]["m1"]["accountCapabilities"] = {}
        client, _, _ = self.client_for(
            FakeResponse(strict_json_bytes(payload))
        )

        with self.assertRaises(self.module.RegistryProtocolError):
            client.discover()

    def test_rejects_wrong_expected_primary_account(self) -> None:
        client, _, _ = self.client_for(
            FakeResponse(strict_json_bytes(session_payload())),
            expected_account_id="m2",
        )

        with self.assertRaises(self.module.RegistryProtocolError):
            client.discover()

    def test_client_close_wipes_credentials_and_prevents_requests(self) -> None:
        client, connection, _ = self.client_for(
            FakeResponse(strict_json_bytes(session_payload()))
        )
        credential = client._credential
        secret_buffer = credential._password

        client.close()

        self.assertEqual(set(secret_buffer), {0})
        self.assertNotIn("secret", repr(client))
        with self.assertRaises(self.module.RegistryClientClosedError):
            client.discover()
        self.assertEqual(connection.requests, [])


class HttpContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def client_for_connection(self, connection: FakeConnection):
        factory = ConnectionFactory([connection])
        patcher = mock.patch.object(
            self.module.http.client,
            "HTTPConnection",
            factory,
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        client = self.module.RegistryClient(
            self.module.BearerCredential(bytearray(b"fixed-local-token")),
            expected_username="admin",
            timeout_seconds=0.25,
        )
        self.addCleanup(client.close)
        return client, factory

    def test_redirect_is_an_error_and_is_never_followed(self) -> None:
        response = FakeResponse(
            b'{"body":"must not be exposed"}',
            status=302,
            headers=(
                ("Content-Type", "application/json"),
                ("Location", "http://example.invalid/stolen"),
            ),
        )
        connection = FakeConnection(response)
        client, factory = self.client_for_connection(connection)

        with self.assertRaises(self.module.RegistryHttpStatusError) as caught:
            client.discover()

        self.assertEqual(caught.exception.status, 302)
        self.assertNotIn("must not be exposed", repr(caught.exception))
        self.assertNotIn("example.invalid", repr(caught.exception))
        self.assertEqual(len(factory.calls), 1)
        self.assertEqual(len(connection.requests), 1)
        self.assertTrue(connection.closed)
        self.assertTrue(response.closed)

    def test_non_success_status_never_retains_or_exposes_body(self) -> None:
        secret = "API_abcdefghijklmnopqrstuvwxyz0123456789-_"
        response = FakeResponse(
            strict_json_bytes({"description": secret}),
            status=401,
        )
        client, _ = self.client_for_connection(FakeConnection(response))

        with self.assertRaises(self.module.RegistryHttpStatusError) as caught:
            client.discover()

        error = caught.exception
        self.assertEqual(error.status, 401)
        self.assertNotIn(secret, str(error))
        self.assertNotIn(secret, repr(error))
        self.assertNotIn(secret, repr(error.__dict__))

    def test_requires_one_json_content_type(self) -> None:
        cases = (
            (("Content-Type", "text/plain"),),
            (
                ("Content-Type", "application/json"),
                ("Content-Type", "application/json"),
            ),
            (("Content-Type", "application/json; charset=latin-1"),),
        )
        for headers in cases:
            with self.subTest(headers=headers):
                client, _ = self.client_for_connection(
                    FakeConnection(
                        FakeResponse(
                            strict_json_bytes(session_payload()),
                            headers=headers,
                        )
                    )
                )
                with self.assertRaises(self.module.RegistryProtocolError):
                    client.discover()

    def test_rejects_declared_or_observed_body_over_fixed_cap(self) -> None:
        cases = (
            FakeResponse(
                strict_json_bytes(session_payload()),
                headers=(
                    ("Content-Type", "application/json"),
                    (
                        "Content-Length",
                        str(self.module.MAX_JSON_BODY_BYTES + 1),
                    ),
                ),
            ),
            FakeResponse(
                b" " * (self.module.MAX_JSON_BODY_BYTES + 1),
                headers=(("Content-Type", "application/json"),),
            ),
        )
        for response in cases:
            with self.subTest(headers=response.getheaders()):
                client, _ = self.client_for_connection(
                    FakeConnection(response)
                )
                with self.assertRaises(self.module.RegistryProtocolError):
                    client.discover()

    def test_malformed_huge_content_length_is_a_redacted_protocol_error(
        self,
    ) -> None:
        canary = "9" * 10_000
        response = FakeResponse(
            strict_json_bytes(session_payload()),
            headers=(
                ("Content-Type", "application/json"),
                ("Content-Length", canary),
            ),
        )
        client, _ = self.client_for_connection(FakeConnection(response))

        with self.assertRaises(self.module.RegistryProtocolError) as caught:
            client.discover()

        self.assertNotIsInstance(caught.exception, ValueError)
        self.assertNotIn(canary, str(caught.exception))
        self.assertNotIn(canary, repr(caught.exception))

    def test_rejects_duplicate_keys_and_floating_point_json(self) -> None:
        valid = strict_json_bytes(session_payload())
        cases = (
            valid.replace(
                b'"state":"1"',
                b'"state":"1","state":"2"',
            ),
            valid.replace(b'"state":"1"', b'"state":1.5'),
            valid.replace(b'"state":"1"', b'"state":NaN'),
        )
        for payload in cases:
            with self.subTest(payload=payload):
                client, _ = self.client_for_connection(
                    FakeConnection(FakeResponse(payload))
                )
                with self.assertRaises(self.module.RegistryProtocolError):
                    client.discover()

    def test_timeout_closes_connection_and_redacts_transport_error(self) -> None:
        timeout = socket.timeout("API_secret_from_socket")
        connection = FakeConnection(None, request_error=timeout)
        client, _ = self.client_for_connection(connection)

        with self.assertRaises(self.module.RegistryTransportError) as caught:
            client.discover()

        self.assertTrue(connection.closed)
        self.assertNotIn("API_secret_from_socket", str(caught.exception))
        self.assertNotIn("API_secret_from_socket", repr(caught.exception))

    def test_connection_setup_failure_is_typed_and_redacted(self) -> None:
        def fail_connection(_host, _port, timeout):
            self.assertEqual(timeout, 0.25)
            raise socket.timeout("API_secret_from_connect")

        patcher = mock.patch.object(
            self.module.http.client,
            "HTTPConnection",
            fail_connection,
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        client = self.module.RegistryClient(
            self.module.BearerCredential(bytearray(b"fixed-token")),
            expected_username="admin",
            timeout_seconds=0.25,
        )
        self.addCleanup(client.close)

        with self.assertRaises(self.module.RegistryTransportError) as caught:
            client.discover()

        self.assertNotIn("API_secret_from_connect", str(caught.exception))
        self.assertNotIn("API_secret_from_connect", repr(caught.exception))

    def test_rejects_truncated_declared_body(self) -> None:
        payload = strict_json_bytes(session_payload())
        response = FakeResponse(
            payload,
            headers=(
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(payload) + 1)),
            ),
        )
        client, _ = self.client_for_connection(FakeConnection(response))

        with self.assertRaises(self.module.RegistryProtocolError):
            client.discover()

    def test_cleanup_failure_is_redacted_and_does_not_skip_connection_close(
        self,
    ) -> None:
        canary = "API_cleanup_secret_canary"
        response = FakeResponse(
            strict_json_bytes(session_payload()),
            close_error=OSError(canary),
        )
        connection = FakeConnection(response)
        client, _ = self.client_for_connection(connection)

        with self.assertRaises(self.module.RegistryTransportError) as caught:
            client.discover()

        self.assertTrue(response.closed)
        self.assertTrue(connection.closed)
        self.assertEqual(client._credential._issued_headers, [])
        self.assertNotIn(canary, str(caught.exception))
        self.assertNotIn(canary, repr(caught.exception))
        self.assertNotIn(canary, repr(caught.exception.__dict__))

    def test_cleanup_failure_never_masks_a_primary_protocol_error(self) -> None:
        response = FakeResponse(
            b'{"secret":"must-not-be-read"}',
            status=401,
            close_error=OSError("cleanup-canary"),
        )
        connection = FakeConnection(
            response,
            close_error=OSError("connection-cleanup-canary"),
        )
        client, _ = self.client_for_connection(connection)

        with self.assertRaises(self.module.RegistryHttpStatusError) as caught:
            client.discover()

        self.assertEqual(caught.exception.status, 401)
        self.assertTrue(response.closed)
        self.assertTrue(connection.closed)
        self.assertNotIn("cleanup-canary", repr(caught.exception))

    def test_authorization_cleanup_failure_still_closes_other_resources(
        self,
    ) -> None:
        response = FakeResponse(strict_json_bytes(session_payload()))
        connection = FakeConnection(response)
        client, _ = self.client_for_connection(connection)
        canary = "authorization-cleanup-secret"

        with mock.patch.object(
            client._credential,
            "_release_header",
            side_effect=OSError(canary),
        ):
            with self.assertRaises(
                self.module.RegistryTransportError
            ) as caught:
                client.discover()

        self.assertTrue(response.closed)
        self.assertTrue(connection.closed)
        self.assertNotIn(canary, str(caught.exception))
        self.assertNotIn(canary, repr(caught.exception))

    def test_cleanup_cancellation_propagates_after_other_cleanup(self) -> None:
        response = FakeResponse(
            strict_json_bytes(session_payload()),
            close_error=KeyboardInterrupt(),
        )
        connection = FakeConnection(response)
        client, _ = self.client_for_connection(connection)

        with self.assertRaises(KeyboardInterrupt):
            client.discover()

        self.assertTrue(response.closed)
        self.assertTrue(connection.closed)


class QueryContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def connected_client(
        self,
        registry_connections: list[FakeConnection],
    ):
        session_connection = FakeConnection(
            FakeResponse(strict_json_bytes(session_payload()))
        )
        factory = ConnectionFactory(
            [session_connection, *registry_connections]
        )
        patcher = mock.patch.object(
            self.module.http.client,
            "HTTPConnection",
            factory,
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        client = self.module.RegistryClient(
            self.module.BearerCredential(bytearray(b"fixed-token")),
            expected_username="admin",
        )
        self.addCleanup(client.close)
        client.discover()
        return client, factory

    def test_named_query_uses_one_live_approved_bounded_first_page(self) -> None:
        query_connection = DynamicConnection(
            lambda request: jmap_response(
                request,
                query_payload(ids=["a1", "a2"], total=2),
            )
        )
        client, factory = self.connected_client([query_connection])

        ids = client.query_named_ids(
            "Account",
            "dashboard-management",
            page_limit=2,
        )

        self.assertEqual(ids, ("a1", "a2"))
        self.assertEqual(len(factory.calls), 2)
        self.assertEqual(len(query_connection.requests), 1)
        body = json.loads(
            bytes(query_connection.requests[0]["body"]).decode("utf-8")
        )
        self.assertEqual(
            body["using"],
            [
                "urn:ietf:params:jmap:core",
                "urn:stalwart:jmap",
            ],
        )
        self.assertEqual(
            body["methodCalls"][0][0],
            "x:Account/query",
        )
        self.assertEqual(
            body["methodCalls"][0][1],
            {
                "accountId": "m1",
                "calculateTotal": True,
                "filter": {"name": "dashboard-management"},
                "limit": 2,
                "position": 0,
                "sort": [],
            },
        )

    def test_description_query_uses_exact_bounded_filter(self) -> None:
        query_connection = DynamicConnection(
            lambda request: jmap_response(
                request,
                query_payload(ids=["tracer-1"], total=1),
            )
        )
        client, factory = self.connected_client([query_connection])

        ids = client.query_described_ids(
            "Tracer",
            "mail-sandbox debug stdout",
            page_limit=2,
        )

        self.assertEqual(ids, ("tracer-1",))
        self.assertEqual(len(factory.calls), 2)
        body = json.loads(
            bytes(query_connection.requests[0]["body"]).decode("utf-8")
        )
        self.assertEqual(
            body["methodCalls"][0][1]["filter"],
            {"description": "mail-sandbox debug stdout"},
        )

    def test_accepts_source_query_and_optional_envelope_shapes(self) -> None:
        payload = query_payload(
            ids=["a1"],
            total=1,
            query_state="opaque/state:rev-β",
        )
        payload.pop("accountId")
        payload["canCalculateChanges"] = False
        connection = DynamicConnection(
            lambda request: jmap_response(
                request,
                payload,
                session_state=ABSENT,
                created_ids={
                    "client/creation:opaque": "provider/object:opaque",
                },
            )
        )
        client, factory = self.connected_client([connection])

        ids = client.query_named_ids("Account", "admin")

        self.assertEqual(ids, ("a1",))
        self.assertEqual(len(factory.calls), 2)
        self.assertEqual(len(connection.requests), 1)

    def test_accepts_opaque_non_hex_session_state(self) -> None:
        connection = DynamicConnection(
            lambda request: jmap_response(
                request,
                query_payload(),
                session_state="provider/state:revision-2026-β",
            )
        )
        client, _ = self.connected_client([connection])

        self.assertEqual(client.query_named_ids("Account", "admin"), ())

    def test_rejects_malformed_optional_envelope_native_types(self) -> None:
        cases = (
            {"session_state": True},
            {"session_state": ""},
            {"session_state": "x" * 4097},
            {"created_ids": []},
            {"created_ids": {"client": False}},
            {"created_ids": {"": "provider"}},
        )
        for case in cases:
            with self.subTest(case=case):
                connection = DynamicConnection(
                    lambda request, options=case: jmap_response(
                        request,
                        query_payload(),
                        **options,
                    )
                )
                client, _ = self.connected_client([connection])

                with self.assertRaises(self.module.RegistryProtocolError):
                    client.query_named_ids("Account", "admin")

    def test_requires_method_responses_and_rejects_unknown_envelope_members(
        self,
    ) -> None:
        def responder_for(case: str):
            def respond(request):
                if case == "missing":
                    value = {"sessionState": "opaque"}
                elif case == "native-type":
                    value = {"methodResponses": {}}
                else:
                    body = json.loads(bytes(request["body"]).decode("utf-8"))
                    method, _arguments, call_id = body["methodCalls"][0]
                    value = {
                        "methodResponses": [
                            [method, query_payload(), call_id],
                        ],
                        "providerExtension": {},
                    }
                return FakeResponse(strict_json_bytes(value))

            return respond

        for case in ("missing", "native-type", "unknown-member"):
            with self.subTest(case=case):
                client, _ = self.connected_client(
                    [DynamicConnection(responder_for(case))]
                )

                with self.assertRaises(self.module.RegistryProtocolError):
                    client.query_named_ids("Account", "admin")

    def test_rejects_call_name_id_and_cardinality_mismatches(self) -> None:
        def responder_for(case: str):
            def respond(request):
                body = json.loads(bytes(request["body"]).decode("utf-8"))
                call_id = body["methodCalls"][0][2]
                if case == "name":
                    return jmap_response(
                        request,
                        query_payload(),
                        response_name="x:Domain/query",
                    )
                if case == "id":
                    return jmap_response(
                        request,
                        query_payload(),
                        response_call_id=f"{call_id}-wrong",
                    )
                return jmap_response(
                    request,
                    query_payload(),
                    extra_responses=[
                        ["x:Account/query", query_payload(), call_id]
                    ],
                )

            return respond

        for case in ("name", "id", "cardinality"):
            with self.subTest(case=case):
                client, _ = self.connected_client(
                    [DynamicConnection(responder_for(case))]
                )
                with self.assertRaises(self.module.RegistryProtocolError):
                    client.query_named_ids("Account", "admin")

    def test_method_error_is_typed_and_never_exposes_description(self) -> None:
        secret = "API_abcdefghijklmnopqrstuvwxyz0123456789-_"

        def responder(request):
            return jmap_response(
                request,
                {
                    "description": f"rejected {secret}",
                    "type": "forbidden",
                },
                response_name="error",
            )

        client, _ = self.connected_client([DynamicConnection(responder)])

        with self.assertRaises(self.module.RegistryMethodError) as caught:
            client.query_named_ids("Account", "admin")

        error = caught.exception
        self.assertEqual(error.method, "x:Account/query")
        self.assertEqual(error.error_type, "forbidden")
        self.assertNotIn(secret, str(error))
        self.assertNotIn(secret, repr(error))
        self.assertNotIn(secret, repr(error.__dict__))

    def test_rejects_malformed_or_incomplete_first_page_native_types(
        self,
    ) -> None:
        cases = {
            "can-calculate-int": {
                **query_payload(),
                "canCalculateChanges": 1,
            },
            "can-calculate-text": {
                **query_payload(),
                "canCalculateChanges": "false",
            },
            "missing-total": {
                key: value
                for key, value in query_payload().items()
                if key != "total"
            },
            "position-bool": query_payload(position=False),
            "wrong-position": query_payload(position=1),
            "total-bool": query_payload(total=True),
            "query-state-object": query_payload(query_state={}),
            "duplicate-ids": query_payload(ids=["a1", "a1"], total=2),
            "incomplete-first-page": query_payload(ids=["a1"], total=2),
            "wrong-account": query_payload(account_id="other"),
        }
        for case, page in cases.items():
            with self.subTest(case=case):
                connection = DynamicConnection(
                    lambda request, value=page: jmap_response(
                        request,
                        value,
                    )
                )
                client, factory = self.connected_client([connection])
                with self.assertRaises(self.module.RegistryProtocolError):
                    client.query_named_ids(
                        "Account",
                        "admin",
                        page_limit=2,
                    )
                self.assertEqual(len(factory.calls), 2)
                self.assertEqual(len(connection.requests), 1)

    def test_rejects_unbounded_declared_query_total(self) -> None:
        connection = DynamicConnection(
            lambda request: jmap_response(
                request,
                query_payload(
                    ids=["a1"],
                    total=self.module.MAX_QUERY_IDS + 1,
                ),
            )
        )
        client, _ = self.connected_client([connection])

        with self.assertRaises(self.module.RegistryProtocolError):
            client.query_named_ids("Account", "admin")


class GetContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def connected_client(
        self,
        registry_connections: list[FakeConnection],
    ):
        connections = [
            FakeConnection(
                FakeResponse(strict_json_bytes(session_payload()))
            ),
            *registry_connections,
        ]
        factory = ConnectionFactory(connections)
        patcher = mock.patch.object(
            self.module.http.client,
            "HTTPConnection",
            factory,
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        client = self.module.RegistryClient(
            self.module.BearerCredential(bytearray(b"fixed-token")),
            expected_username="admin",
        )
        self.addCleanup(client.close)
        client.discover()
        return client

    def test_gets_one_singleton_with_exact_id_and_redacted_model(self) -> None:
        connection = DynamicConnection(
            lambda request: jmap_response(
                request,
                get_payload(
                    values=[
                        {
                            "defaultHostname": "stalwart.local.test",
                            "id": "singleton",
                        }
                    ]
                ),
            )
        )
        client = self.connected_client([connection])

        result = client.get_singleton(
            "SystemSettings",
            properties=("id", "defaultHostname"),
        )

        self.assertEqual(result.object_type, "SystemSettings")
        self.assertEqual(result.object_id, "singleton")
        self.assertEqual(result.account_id, "m1")
        self.assertEqual(
            result.value(),
            {
                "defaultHostname": "stalwart.local.test",
                "id": "singleton",
            },
        )
        self.assertNotIn("stalwart.local.test", repr(result))
        body = json.loads(
            bytes(connection.requests[0]["body"]).decode("utf-8")
        )
        self.assertEqual(body["methodCalls"][0][0], "x:SystemSettings/get")
        self.assertEqual(
            body["methodCalls"][0][1],
            {
                "accountId": "m1",
                "ids": ["singleton"],
                "properties": ["id", "defaultHostname"],
            },
        )

    def test_get_accepts_source_shape_without_account_id(self) -> None:
        payload = get_payload(values=[{"id": "a1", "name": "source-shape"}])
        payload.pop("accountId")
        connection = DynamicConnection(
            lambda request: jmap_response(
                request,
                payload,
                session_state=ABSENT,
            )
        )
        client = self.connected_client([connection])

        result = client.get_one("Account", "a1", properties=("id", "name"))

        self.assertEqual(
            result.value(),
            {"id": "a1", "name": "source-shape"},
        )

    def test_single_get_rejects_not_found_mismatch_or_extra_objects(self) -> None:
        cases = (
            get_payload(not_found=["a1"]),
            get_payload(values=[{"id": "other"}]),
            get_payload(values=[{"id": "a1"}, {"id": "a2"}]),
            get_payload(
                account_id="other",
                values=[{"id": "a1"}],
            ),
            {
                **get_payload(values=[{"id": "a1"}]),
                "accountId": False,
            },
        )
        for payload in cases:
            with self.subTest(payload=payload):
                connection = DynamicConnection(
                    lambda request, value=payload: jmap_response(
                        request,
                        value,
                    )
                )
                client = self.connected_client([connection])
                with self.assertRaises(self.module.RegistryProtocolError):
                    client.get_one("Account", "a1", properties=("id",))

    def test_exact_not_found_is_typed_for_reconciliation(self) -> None:
        connection = DynamicConnection(
            lambda request: jmap_response(
                request,
                get_payload(not_found=["singleton"]),
            )
        )
        client = self.connected_client([connection])

        with self.assertRaises(
            self.module.RegistryNotFoundError
        ) as caught:
            client.get_singleton("SystemSettings", properties=("id",))

        self.assertEqual(caught.exception.object_type, "SystemSettings")
        self.assertEqual(caught.exception.object_id, "singleton")

    def test_credentials_are_queried_and_read_in_explicit_owner_scope(self) -> None:
        query_connection = DynamicConnection(
            lambda request: jmap_response(
                request,
                query_payload(
                    account_id="owner1",
                    ids=["key1"],
                    total=1,
                ),
            )
        )
        get_connection = DynamicConnection(
            lambda request: jmap_response(
                request,
                get_payload(
                    account_id="owner1",
                    values=[
                        {
                            "allowedIps": {},
                            "description": "management",
                            "expiresAt": None,
                            "id": "key1",
                            "permissions": {
                                "@type": "Replace",
                                "permissions": {"authenticate": True},
                            },
                        }
                    ],
                ),
            )
        )
        client = self.connected_client(
            [query_connection, get_connection]
        )

        ids = client.query_credential_ids("ApiKey", "owner1")
        credential = client.get_credential("ApiKey", "owner1", "key1")

        self.assertEqual(ids, ("key1",))
        self.assertEqual(credential.credential_type, "ApiKey")
        self.assertEqual(credential.credential_id, "key1")
        self.assertEqual(credential.account_id, "owner1")
        self.assertEqual(credential.description, "management")
        self.assertEqual(
            credential.permissions(),
            {
                "@type": "Replace",
                "permissions": {"authenticate": True},
            },
        )
        self.assertEqual(credential.allowed_ips(), {})
        self.assertNotIn("management", repr(credential))

        query_body = json.loads(
            bytes(query_connection.requests[0]["body"]).decode("utf-8")
        )
        get_body = json.loads(
            bytes(get_connection.requests[0]["body"]).decode("utf-8")
        )
        self.assertEqual(
            query_body["methodCalls"][0],
            [
                "x:ApiKey/query",
                {
                    "accountId": "owner1",
                    "calculateTotal": True,
                    "filter": {},
                    "limit": 100,
                    "position": 0,
                    "sort": [],
                },
                query_body["methodCalls"][0][2],
            ],
        )
        self.assertEqual(
            get_body["methodCalls"][0],
            [
                "x:ApiKey/get",
                {
                    "accountId": "owner1",
                    "ids": ["key1"],
                    "properties": [
                        "id",
                        "description",
                        "expiresAt",
                        "permissions",
                        "allowedIps",
                    ],
                },
                get_body["methodCalls"][0][2],
            ],
        )

    def test_credential_get_rejects_secret_or_malformed_projection(self) -> None:
        values = [
            {
                "allowedIps": {},
                "description": "management",
                "expiresAt": None,
                "id": "key1",
                "permissions": {},
                "secret": "****",
            },
            {
                "allowedIps": [],
                "description": "management",
                "expiresAt": None,
                "id": "key1",
                "permissions": {},
            },
        ]
        for value in values:
            with self.subTest(value=value):
                connection = DynamicConnection(
                    lambda request, item=value: jmap_response(
                        request,
                        get_payload(
                            account_id="owner1",
                            values=[item],
                        ),
                    )
                )
                client = self.connected_client([connection])
                with self.assertRaises(self.module.RegistryProtocolError):
                    client.get_credential("ApiKey", "owner1", "key1")

    def test_rejects_non_owner_scoped_credential_types(self) -> None:
        client = self.connected_client([])
        for credential_type in ("Password", "Account", "apiKey"):
            with self.subTest(credential_type=credential_type):
                with self.assertRaises(ValueError):
                    client.query_credential_ids(
                        credential_type,
                        "owner1",
                    )


class SetContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def connected_client(
        self,
        registry_connections: list[FakeConnection],
    ):
        connections = [
            FakeConnection(
                FakeResponse(strict_json_bytes(session_payload()))
            ),
            *registry_connections,
        ]
        factory = ConnectionFactory(connections)
        patcher = mock.patch.object(
            self.module.http.client,
            "HTTPConnection",
            factory,
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        client = self.module.RegistryClient(
            self.module.BearerCredential(bytearray(b"fixed-token")),
            expected_username="admin",
        )
        self.addCleanup(client.close)
        client.discover()
        return client, factory

    def test_create_validates_exact_created_result(self) -> None:
        def responder(request):
            body = json.loads(bytes(request["body"]).decode("utf-8"))
            args = body["methodCalls"][0][1]
            creation_id = next(iter(args["create"]))
            return jmap_response(
                request,
                {
                    "created": {creation_id: {"id": "domain1"}},
                },
                session_state=ABSENT,
                created_ids={creation_id: "domain1"},
            )

        connection = DynamicConnection(responder)
        client, _ = self.connected_client([connection])
        desired = {"name": "local.test"}

        result = client.create("Domain", desired)

        self.assertEqual(result.operation, "create")
        self.assertEqual(result.object_type, "Domain")
        self.assertEqual(result.object_id, "domain1")
        self.assertEqual(result.account_id, "m1")
        self.assertEqual(desired, {"name": "local.test"})
        body = json.loads(
            bytes(connection.requests[0]["body"]).decode("utf-8")
        )
        method, args, _ = body["methodCalls"][0]
        self.assertEqual(method, "x:Domain/set")
        self.assertEqual(args["accountId"], "m1")
        self.assertEqual(list(args["create"].values()), [desired])
        self.assertEqual(set(args), {"accountId", "create"})

    def test_update_and_destroy_validate_exact_results(self) -> None:
        update_connection = DynamicConnection(
            lambda request: jmap_response(
                request,
                {
                    "updated": {"domain1": {}},
                },
                session_state=ABSENT,
            )
        )
        destroy_connection = DynamicConnection(
            lambda request: jmap_response(
                request,
                {
                    "accountId": "m1",
                    "destroyed": ["domain1"],
                },
            )
        )
        client, _ = self.connected_client(
            [update_connection, destroy_connection]
        )

        updated = client.update(
            "Domain",
            "domain1",
            {"description": "updated"},
        )
        destroyed = client.destroy("Domain", "domain1")

        self.assertEqual(updated.operation, "update")
        self.assertEqual(destroyed.operation, "destroy")
        update_body = json.loads(
            bytes(update_connection.requests[0]["body"]).decode("utf-8")
        )
        destroy_body = json.loads(
            bytes(destroy_connection.requests[0]["body"]).decode("utf-8")
        )
        self.assertEqual(
            update_body["methodCalls"][0][1],
            {
                "accountId": "m1",
                "update": {
                    "domain1": {"description": "updated"},
                },
            },
        )
        self.assertEqual(
            destroy_body["methodCalls"][0][1],
            {
                "accountId": "m1",
                "destroy": ["domain1"],
            },
        )

    def test_update_rejects_conflicting_or_malformed_source_outcomes(
        self,
    ) -> None:
        cases = (
            {"updated": {"domain1": {}, "other": {}}},
            {"updated": {"domain1": True}},
            {
                "updated": {"domain1": {}},
                "notUpdated": {
                    "domain1": {"type": "invalidProperties"},
                },
            },
            {
                "updated": {"domain1": {}},
                "destroyed": ["domain1"],
            },
            {
                "accountId": False,
                "updated": {"domain1": {}},
            },
            {
                "accountId": "other",
                "updated": {"domain1": {}},
            },
        )
        for payload in cases:
            with self.subTest(payload=payload):
                connection = DynamicConnection(
                    lambda request, value=payload: jmap_response(
                        request,
                        value,
                    )
                )
                client, _ = self.connected_client([connection])

                with self.assertRaises(self.module.RegistryProtocolError):
                    client.update("Domain", "domain1", {"name": "updated"})

    def test_set_errors_are_typed_and_redact_server_description(self) -> None:
        secret = "API_abcdefghijklmnopqrstuvwxyz0123456789-_"
        cases = (
            (
                "create",
                "notCreated",
                lambda client: client.create("Domain", {"name": "x"}),
            ),
            (
                "update",
                "notUpdated",
                lambda client: client.update(
                    "Domain",
                    "domain1",
                    {"name": "x"},
                ),
            ),
            (
                "destroy",
                "notDestroyed",
                lambda client: client.destroy("Domain", "domain1"),
            ),
        )
        for operation, error_member, invoke in cases:
            with self.subTest(operation=operation):
                def responder(request, member=error_member):
                    body = json.loads(
                        bytes(request["body"]).decode("utf-8")
                    )
                    args = body["methodCalls"][0][1]
                    if "create" in args:
                        target = next(iter(args["create"]))
                    elif "update" in args:
                        target = next(iter(args["update"]))
                    else:
                        target = args["destroy"][0]
                    return jmap_response(
                        request,
                        {
                            "accountId": "m1",
                            member: {
                                target: {
                                    "description": f"rejected {secret}",
                                    "type": "invalidProperties",
                                }
                            },
                        },
                    )

                client, _ = self.connected_client(
                    [DynamicConnection(responder)]
                )
                with self.assertRaises(
                    self.module.RegistrySetError
                ) as caught:
                    invoke(client)
                error = caught.exception
                self.assertEqual(error.operation, operation)
                self.assertEqual(error.error_type, "invalidProperties")
                self.assertNotIn(secret, str(error))
                self.assertNotIn(secret, repr(error))
                self.assertNotIn(secret, repr(error.__dict__))

    def test_rejects_malformed_or_conflicting_set_success(self) -> None:
        cases = (
            {"accountId": "m1", "created": {"c": {}}},
            {
                "accountId": "m1",
                "created": {
                    "c": {"id": "domain1"},
                    "other": {"id": "domain2"},
                },
            },
            {
                "accountId": "m1",
                "created": {"c": {"id": "domain1"}},
                "notCreated": {
                    "c": {"type": "invalidProperties"},
                },
            },
            {
                "accountId": "m1",
                "created": {"c": {"id": "domain1", "extra": True}},
            },
        )
        for payload in cases:
            with self.subTest(payload=payload):
                def responder(request, value=payload):
                    body = json.loads(
                        bytes(request["body"]).decode("utf-8")
                    )
                    creation_id = next(
                        iter(body["methodCalls"][0][1]["create"])
                    )
                    adjusted = json.loads(json.dumps(value))
                    if "created" in adjusted and "c" in adjusted["created"]:
                        adjusted["created"][creation_id] = adjusted[
                            "created"
                        ].pop("c")
                    if (
                        "notCreated" in adjusted
                        and "c" in adjusted["notCreated"]
                    ):
                        adjusted["notCreated"][creation_id] = adjusted[
                            "notCreated"
                        ].pop("c")
                    return jmap_response(request, adjusted)

                client, _ = self.connected_client(
                    [DynamicConnection(responder)]
                )
                with self.assertRaises(self.module.RegistryProtocolError):
                    client.create("Domain", {"name": "x"})

    def test_api_key_create_returns_only_wipeable_valid_secret(self) -> None:
        raw_secret = "API_" + ("A" * 38)

        def responder(request):
            body = json.loads(bytes(request["body"]).decode("utf-8"))
            args = body["methodCalls"][0][1]
            creation_id = next(iter(args["create"]))
            return jmap_response(
                request,
                {
                    "accountId": "owner1",
                    "created": {
                        creation_id: {
                            "id": "key1",
                            "secret": raw_secret,
                        }
                    },
                },
            )

        connection = DynamicConnection(responder)
        client, _ = self.connected_client([connection])
        desired = {
            "allowedIps": {},
            "description": "management",
            "permissions": {
                "@type": "Replace",
                "permissions": {"authenticate": True},
            },
        }

        result = client.create_api_key("owner1", desired)
        secret_buffer = result.secret._buffer
        copied = result.secret.copy_bytes()

        self.assertEqual(result.account_id, "owner1")
        self.assertEqual(result.credential_id, "key1")
        self.assertEqual(bytes(copied).decode("ascii"), raw_secret)
        self.assertNotIn(raw_secret, repr(result))
        self.assertNotIn(raw_secret, repr(result.__dict__))
        self.assertNotIn(raw_secret, repr(result.secret))
        body = json.loads(
            bytes(connection.requests[0]["body"]).decode("utf-8")
        )
        method, args, _ = body["methodCalls"][0]
        self.assertEqual(method, "x:ApiKey/set")
        self.assertEqual(args["accountId"], "owner1")
        self.assertEqual(list(args["create"].values()), [desired])

        result.close()
        self.assertEqual(set(secret_buffer), {0})
        with self.assertRaises(self.module.CredentialClosedError):
            result.secret.copy_bytes()
        for index in range(len(copied)):
            copied[index] = 0

    def test_api_key_create_rejects_malformed_secret_without_leaking_it(self) -> None:
        malformed = "API_" + ("!" * 38)

        def responder(request):
            body = json.loads(bytes(request["body"]).decode("utf-8"))
            args = body["methodCalls"][0][1]
            creation_id = next(iter(args["create"]))
            return jmap_response(
                request,
                {
                    "accountId": "owner1",
                    "created": {
                        creation_id: {
                            "id": "key1",
                            "secret": malformed,
                        }
                    },
                },
            )

        client, _ = self.connected_client(
            [DynamicConnection(responder)]
        )

        with self.assertRaises(self.module.RegistryProtocolError) as caught:
            client.create_api_key(
                "owner1",
                {
                    "allowedIps": {},
                    "description": "management",
                    "permissions": {},
                },
            )

        self.assertNotIn(malformed, str(caught.exception))
        self.assertNotIn(malformed, repr(caught.exception))
        self.assertNotIn(malformed, repr(caught.exception.__dict__))

    def test_rejects_float_or_oversized_outgoing_json_before_connect(self) -> None:
        client, factory = self.connected_client([])
        existing_calls = len(factory.calls)

        with self.assertRaises(ValueError):
            client.create("Domain", {"ratio": 1.5})
        with self.assertRaises(ValueError):
            client.create(
                "Domain",
                {"description": "x" * self.module.MAX_JSON_BODY_BYTES},
            )

        self.assertEqual(len(factory.calls), existing_calls)

    def test_generic_create_rejects_secret_returning_credential_types(self) -> None:
        client, factory = self.connected_client([])
        existing_calls = len(factory.calls)

        for object_type in ("ApiKey", "AppPassword"):
            with self.subTest(object_type=object_type):
                with self.assertRaises(ValueError):
                    client.create(
                        object_type,
                        {"description": "unsafe generic creation"},
                    )

        self.assertEqual(len(factory.calls), existing_calls)


if __name__ == "__main__":
    unittest.main()
