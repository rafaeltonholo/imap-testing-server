#!/usr/bin/env python3
"""Fail-closed stdlib transport for Stalwart v0.16.14 Registry calls.

The transport is intentionally pinned to the loopback listener exposed by the
v0.16 migration overlay.  It does not accept configurable origins or follow
redirects.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import http.client
import json
import math
import re
import secrets
from typing import Final


REGISTRY_HOST: Final = "127.0.0.1"
REGISTRY_PORT: Final = 18080
SESSION_PATH: Final = "/.well-known/jmap"
API_PATH: Final = "/jmap/"
API_URL: Final = "http://127.0.0.1:18080/jmap/"
CORE_CAPABILITY: Final = "urn:ietf:params:jmap:core"
STALWART_CAPABILITY: Final = "urn:stalwart:jmap"
MAX_JSON_BODY_BYTES: Final = 256 * 1024
MAX_CREDENTIAL_BYTES: Final = 4096
MAX_QUERY_IDS: Final = 10_000
MAX_OPAQUE_TEXT_BYTES: Final = 4096

_SAFE_ID = re.compile(r"[A-Za-z0-9_-]{1,255}")
_OBJECT_TYPE = re.compile(r"[A-Za-z][A-Za-z0-9]{0,63}")
_ERROR_TYPE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
_PROPERTY = re.compile(r"(?:@type|[A-Za-z][A-Za-z0-9]{0,63})")
_CREDENTIAL_TYPES: Final = frozenset({"ApiKey", "AppPassword"})
_API_KEY = re.compile(r"API_[A-Za-z0-9_-]{38}")
_SET_MEMBERS: Final = frozenset(
    {
        "accountId",
        "created",
        "destroyed",
        "newState",
        "notCreated",
        "notDestroyed",
        "notUpdated",
        "oldState",
        "updated",
    }
)


class RegistryError(RuntimeError):
    """Base class for redacted Registry transport failures."""


class CredentialClosedError(RegistryError):
    """A credential was used after its sensitive buffers were wiped."""


class RegistryClientClosedError(RegistryError):
    """The client was used after close()."""


class RegistryTransportError(RegistryError):
    """The fixed loopback HTTP exchange failed."""


class RegistryHttpStatusError(RegistryTransportError):
    """The fixed endpoint returned a non-success status."""

    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(f"unexpected HTTP status {status}")


class RegistryProtocolError(RegistryError):
    """The peer returned a response outside the pinned protocol contract."""


class RegistryNotFoundError(RegistryProtocolError):
    """An exact singleton/get target was authoritatively absent."""

    def __init__(self, object_type: str, object_id: str) -> None:
        self.object_type = object_type
        self.object_id = object_id
        super().__init__(f"{object_type} {object_id} was not found")


class RegistryMethodError(RegistryError):
    """A JMAP method-level error with its description deliberately omitted."""

    def __init__(self, method: str, error_type: str) -> None:
        self.method = method
        self.error_type = error_type
        super().__init__(f"{method} failed with {error_type}")


class RegistrySetError(RegistryError):
    """One Registry set operation was rejected; descriptions stay discarded."""

    def __init__(
        self,
        operation: str,
        object_type: str,
        object_id: str,
        error_type: str,
    ) -> None:
        self.operation = operation
        self.object_type = object_type
        self.object_id = object_id
        self.error_type = error_type
        super().__init__(
            f"{operation} {object_type} {object_id} failed with {error_type}"
        )


def _wipe(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


def _secret_bytes(value: str | bytes | bytearray, field: str) -> bytearray:
    if isinstance(value, str):
        try:
            encoded = value.encode("utf-8", "strict")
        except UnicodeError:
            raise ValueError(f"{field} is not valid UTF-8") from None
        result = bytearray(encoded)
    elif isinstance(value, (bytes, bytearray)):
        result = bytearray(value)
    else:
        raise TypeError(f"{field} must be text or bytes")
    if not result or len(result) > MAX_CREDENTIAL_BYTES:
        _wipe(result)
        raise ValueError(f"{field} has an invalid length")
    return result


class _MutableCredential:
    def __init__(self) -> None:
        self._closed = False
        self._issued_headers: list[bytearray] = []

    @property
    def closed(self) -> bool:
        return self._closed

    def _track_header(self, header: bytearray) -> bytearray:
        if self._closed:
            _wipe(header)
            raise CredentialClosedError("credential is closed")
        self._issued_headers.append(header)
        return header

    def _release_header(self, header: bytearray) -> None:
        _wipe(header)
        for index, issued in enumerate(self._issued_headers):
            if issued is header:
                del self._issued_headers[index]
                break

    def _close_headers(self) -> None:
        for header in self._issued_headers:
            _wipe(header)
        self._issued_headers.clear()
        self._closed = True

    def __enter__(self):
        if self._closed:
            raise CredentialClosedError("credential is closed")
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


class BasicCredential(_MutableCredential):
    """Mutable Basic-auth material whose buffers are wiped on close."""

    def __init__(
        self,
        username: str | bytes | bytearray,
        password: str | bytes | bytearray,
    ) -> None:
        super().__init__()
        self._username = _secret_bytes(username, "username")
        try:
            self._password = _secret_bytes(password, "password")
        except BaseException:
            _wipe(self._username)
            self._closed = True
            raise
        if b":" in self._username:
            self.close()
            raise ValueError("username cannot contain ':'")

    def _authorization_header(self) -> bytearray:
        if self._closed:
            raise CredentialClosedError("credential is closed")
        joined = bytearray()
        joined.extend(self._username)
        joined.extend(b":")
        joined.extend(self._password)
        encoded = base64.b64encode(joined)
        _wipe(joined)
        header = bytearray(b"Basic ")
        header.extend(encoded)
        return self._track_header(header)

    def close(self) -> None:
        if not self._closed:
            _wipe(self._username)
            _wipe(self._password)
            self._close_headers()

    def __repr__(self) -> str:
        return f"BasicCredential(<redacted>, closed={self._closed})"


class BearerCredential(_MutableCredential):
    """Mutable Bearer-auth material whose buffer is wiped on close."""

    def __init__(self, token: str | bytes | bytearray) -> None:
        super().__init__()
        self._token = _secret_bytes(token, "token")
        if any(value < 0x21 or value > 0x7E for value in self._token):
            self.close()
            raise ValueError("token must contain visible ASCII only")

    def _authorization_header(self) -> bytearray:
        if self._closed:
            raise CredentialClosedError("credential is closed")
        header = bytearray(b"Bearer ")
        header.extend(self._token)
        return self._track_header(header)

    def close(self) -> None:
        if not self._closed:
            _wipe(self._token)
            self._close_headers()

    def __repr__(self) -> str:
        return f"BearerCredential(<redacted>, closed={self._closed})"


@dataclass(frozen=True, repr=False)
class RegistrySession:
    username: str
    account_id: str
    api_path: str = API_PATH

    def __repr__(self) -> str:
        return (
            "RegistrySession("
            f"username={self.username!r}, account_id={self.account_id!r}, "
            f"api_path={self.api_path!r})"
        )


@dataclass(frozen=True, repr=False)
class RegistryObject:
    """Immutable, redacted wrapper around one Registry get object."""

    object_type: str
    object_id: str
    account_id: str
    _value_json: str

    def value(self) -> dict[str, object]:
        value = _decode_json(self._value_json.encode("utf-8"))
        if type(value) is not dict:
            raise RegistryProtocolError("stored Registry object is malformed")
        return value

    def __repr__(self) -> str:
        return (
            "RegistryObject("
            f"object_type={self.object_type!r}, "
            f"object_id={self.object_id!r}, "
            f"account_id={self.account_id!r}, value=<redacted>)"
        )


@dataclass(frozen=True, repr=False)
class CredentialRecord:
    """Safe credential metadata; server-returned secret fields are forbidden."""

    credential_type: str
    credential_id: str
    account_id: str
    description: str
    expires_at: str | None
    _permissions_json: str
    _allowed_ips_json: str

    def permissions(self) -> dict[str, object]:
        value = _decode_json(self._permissions_json.encode("utf-8"))
        if type(value) is not dict:
            raise RegistryProtocolError(
                "stored credential permissions are malformed"
            )
        return value

    def allowed_ips(self) -> dict[str, object]:
        value = _decode_json(self._allowed_ips_json.encode("utf-8"))
        if type(value) is not dict:
            raise RegistryProtocolError(
                "stored credential IP restrictions are malformed"
            )
        return value

    def __repr__(self) -> str:
        return (
            "CredentialRecord("
            f"credential_type={self.credential_type!r}, "
            f"credential_id={self.credential_id!r}, "
            f"account_id={self.account_id!r}, metadata=<redacted>)"
        )


@dataclass(frozen=True, repr=False)
class MutationResult:
    operation: str
    object_type: str
    object_id: str
    account_id: str

    def __repr__(self) -> str:
        return (
            "MutationResult("
            f"operation={self.operation!r}, "
            f"object_type={self.object_type!r}, "
            f"object_id={self.object_id!r}, "
            f"account_id={self.account_id!r})"
        )


class ApiKeySecret:
    """A validated Stalwart API key stored only in a wipeable buffer."""

    def __init__(self, value: str) -> None:
        if type(value) is not str or _API_KEY.fullmatch(value) is None:
            raise RegistryProtocolError("API key creation secret is malformed")
        try:
            self._buffer = bytearray(value.encode("ascii", "strict"))
        except UnicodeError:
            raise RegistryProtocolError(
                "API key creation secret is malformed"
            ) from None
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def copy_bytes(self) -> bytearray:
        if self._closed:
            raise CredentialClosedError("API key secret is closed")
        return bytearray(self._buffer)

    def close(self) -> None:
        if not self._closed:
            _wipe(self._buffer)
            self._closed = True

    def __enter__(self):
        if self._closed:
            raise CredentialClosedError("API key secret is closed")
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"ApiKeySecret(<redacted>, closed={self._closed})"


@dataclass(frozen=True, repr=False)
class ApiKeyCreation:
    account_id: str
    credential_id: str
    secret: ApiKeySecret

    def close(self) -> None:
        self.secret.close()

    def __enter__(self):
        if self.secret.closed:
            raise CredentialClosedError("API key creation is closed")
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            "ApiKeyCreation("
            f"account_id={self.account_id!r}, "
            f"credential_id={self.credential_id!r}, secret=<redacted>)"
        )


class RegistryClient:
    """Synchronous one-request-per-connection Registry client."""

    def __init__(
        self,
        credential: BasicCredential | BearerCredential,
        *,
        expected_username: str,
        expected_account_id: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not isinstance(credential, (BasicCredential, BearerCredential)):
            raise TypeError("credential has an unsupported type")
        try:
            if (
                type(expected_username) is not str
                or not expected_username
                or len(expected_username) > 255
                or any(ord(char) < 0x20 for char in expected_username)
            ):
                raise ValueError("expected username is invalid")
            if expected_account_id is not None:
                _validate_id(expected_account_id, "expected account ID")
            if (
                type(timeout_seconds) not in (int, float)
                or (
                    type(timeout_seconds) is float
                    and not math.isfinite(timeout_seconds)
                )
                or timeout_seconds <= 0
                or timeout_seconds > 60
            ):
                raise ValueError("timeout must be between zero and 60 seconds")
        except BaseException:
            credential.close()
            raise
        self._credential = credential
        self._expected_username = expected_username
        self._expected_account_id = expected_account_id
        self._timeout_seconds = float(timeout_seconds)
        self._closed = False
        self._session: RegistrySession | None = None
        self._call_counter = 0
        self._creation_counter = 0

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def session(self) -> RegistrySession:
        self._ensure_open()
        if self._session is None:
            raise RegistryProtocolError("JMAP session has not been discovered")
        return self._session

    def discover(self) -> RegistrySession:
        self._ensure_open()
        payload = self._request_json("GET", SESSION_PATH, None)
        session = _validate_session(
            payload,
            expected_username=self._expected_username,
            expected_account_id=self._expected_account_id,
        )
        self._session = session
        return session

    def query_named_ids(
        self,
        object_type: str,
        name: str,
        *,
        page_limit: int = 100,
    ) -> tuple[str, ...]:
        """Query exact `name` matches in one live-approved bounded page."""

        _validate_object_type(object_type)
        if (
            type(name) is not str
            or not name
            or len(name) > 255
            or any(ord(char) < 0x20 for char in name)
        ):
            raise ValueError("registry object name is invalid")
        return self._query_ids(
            object_type,
            account_id=self.session.account_id,
            filter_value={"name": name},
            page_limit=page_limit,
        )

    def get_one(
        self,
        object_type: str,
        object_id: str,
        *,
        properties: tuple[str, ...] | list[str] | None = None,
        account_id: str | None = None,
    ) -> RegistryObject:
        """Fetch exactly one Registry object and reject partial ambiguity."""

        _validate_object_type(object_type)
        object_id = _validate_id(object_id, "Registry object ID")
        scoped_account = (
            self.session.account_id
            if account_id is None
            else _validate_id(account_id, "Registry account ID")
        )
        arguments: dict[str, object] = {
            "accountId": scoped_account,
            "ids": [object_id],
        }
        if properties is not None:
            arguments["properties"] = list(
                _validate_properties(properties)
            )
        payload = self._call(f"x:{object_type}/get", arguments)
        value = _validate_get_one(
            payload,
            object_type=object_type,
            account_id=scoped_account,
            object_id=object_id,
        )
        return RegistryObject(
            object_type=object_type,
            object_id=object_id,
            account_id=scoped_account,
            _value_json=_canonical_json_text(value),
        )

    def get_singleton(
        self,
        object_type: str,
        *,
        properties: tuple[str, ...] | list[str] | None = None,
    ) -> RegistryObject:
        return self.get_one(
            object_type,
            "singleton",
            properties=properties,
        )

    def query_credential_ids(
        self,
        credential_type: str,
        owner_account_id: str,
        *,
        page_limit: int = 100,
    ) -> tuple[str, ...]:
        """Query API-key or app-password IDs in an explicit owner account."""

        _validate_credential_type(credential_type)
        owner_account_id = _validate_id(
            owner_account_id,
            "credential owner account ID",
        )
        return self._query_ids(
            credential_type,
            account_id=owner_account_id,
            filter_value={},
            page_limit=page_limit,
        )

    def get_credential(
        self,
        credential_type: str,
        owner_account_id: str,
        credential_id: str,
    ) -> CredentialRecord:
        """Fetch a secret-free credential projection in owner scope."""

        _validate_credential_type(credential_type)
        owner_account_id = _validate_id(
            owner_account_id,
            "credential owner account ID",
        )
        credential_id = _validate_id(
            credential_id,
            "credential ID",
        )
        record = self.get_one(
            credential_type,
            credential_id,
            account_id=owner_account_id,
            properties=(
                "id",
                "description",
                "expiresAt",
                "permissions",
                "allowedIps",
            ),
        )
        return _credential_record(
            credential_type,
            owner_account_id,
            credential_id,
            record.value(),
        )

    def create(
        self,
        object_type: str,
        value: dict[str, object],
        *,
        account_id: str | None = None,
    ) -> MutationResult:
        """Create one non-credential Registry object."""

        _validate_object_type(object_type)
        if object_type in _CREDENTIAL_TYPES:
            raise ValueError(
                "secret-returning credentials require a dedicated creator"
            )
        scoped_account = (
            self.session.account_id
            if account_id is None
            else _validate_id(account_id, "Registry account ID")
        )
        creation_id, created = self._create_value(
            object_type,
            value,
            scoped_account,
        )
        if set(created) != {"id"}:
            raise RegistryProtocolError(
                "Registry create result is malformed"
            )
        object_id = _validate_id(
            created.get("id"),
            "created Registry object ID",
        )
        return MutationResult(
            operation="create",
            object_type=object_type,
            object_id=object_id,
            account_id=scoped_account,
        )

    def create_api_key(
        self,
        owner_account_id: str,
        value: dict[str, object],
    ) -> ApiKeyCreation:
        """Create one owner-scoped key and return its one-shot raw secret."""

        owner_account_id = _validate_id(
            owner_account_id,
            "API key owner account ID",
        )
        if type(value) is not dict or not value:
            raise ValueError("API key value must be a non-empty object")
        if {
            "createdAt",
            "credentialId",
            "secret",
        }.intersection(value):
            raise ValueError("API key value contains a server-set property")
        _creation_id, created = self._create_value(
            "ApiKey",
            value,
            owner_account_id,
        )
        if set(created) != {"id", "secret"}:
            raise RegistryProtocolError("API key create result is malformed")
        credential_id = _validate_id(
            created.get("id"),
            "created API key ID",
        )
        raw_secret = created.get("secret")
        if type(raw_secret) is not str:
            raise RegistryProtocolError("API key create secret is malformed")
        try:
            secret = ApiKeySecret(raw_secret)
        finally:
            created["secret"] = None
        return ApiKeyCreation(
            account_id=owner_account_id,
            credential_id=credential_id,
            secret=secret,
        )

    def update(
        self,
        object_type: str,
        object_id: str,
        patch: dict[str, object],
        *,
        account_id: str | None = None,
    ) -> MutationResult:
        """Update exactly one Registry object."""

        _validate_object_type(object_type)
        object_id = _validate_id(object_id, "Registry object ID")
        if type(patch) is not dict or not patch:
            raise ValueError("Registry update must be a non-empty object")
        scoped_account = (
            self.session.account_id
            if account_id is None
            else _validate_id(account_id, "Registry account ID")
        )
        payload = self._call(
            f"x:{object_type}/set",
            {
                "accountId": scoped_account,
                "update": {object_id: patch},
            },
        )
        _validate_set_update(
            payload,
            object_type=object_type,
            object_id=object_id,
            account_id=scoped_account,
        )
        return MutationResult(
            operation="update",
            object_type=object_type,
            object_id=object_id,
            account_id=scoped_account,
        )

    def destroy(
        self,
        object_type: str,
        object_id: str,
        *,
        account_id: str | None = None,
    ) -> MutationResult:
        """Destroy exactly one Registry object."""

        _validate_object_type(object_type)
        object_id = _validate_id(object_id, "Registry object ID")
        scoped_account = (
            self.session.account_id
            if account_id is None
            else _validate_id(account_id, "Registry account ID")
        )
        payload = self._call(
            f"x:{object_type}/set",
            {
                "accountId": scoped_account,
                "destroy": [object_id],
            },
        )
        _validate_set_destroy(
            payload,
            object_type=object_type,
            object_id=object_id,
            account_id=scoped_account,
        )
        return MutationResult(
            operation="destroy",
            object_type=object_type,
            object_id=object_id,
            account_id=scoped_account,
        )

    def close(self) -> None:
        if not self._closed:
            self._session = None
            self._credential.close()
            self._closed = True

    def __enter__(self):
        self._ensure_open()
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            "RegistryClient("
            f"endpoint={REGISTRY_HOST}:{REGISTRY_PORT}, "
            f"closed={self._closed}, credential=<redacted>)"
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise RegistryClientClosedError("registry client is closed")
        if self._credential.closed:
            raise CredentialClosedError("credential is closed")

    def _next_call_id(self) -> str:
        self._call_counter += 1
        return (
            f"registry-{self._call_counter:08x}-"
            f"{secrets.token_hex(8)}"
        )

    def _next_creation_id(self) -> str:
        self._creation_counter += 1
        return (
            f"create-{self._creation_counter:08x}-"
            f"{secrets.token_hex(8)}"
        )

    def _call(
        self,
        method: str,
        arguments: dict[str, object],
    ) -> dict[str, object]:
        self._ensure_open()
        call_id = self._next_call_id()
        request_value = {
            "methodCalls": [[method, arguments, call_id]],
            "using": [CORE_CAPABILITY, STALWART_CAPABILITY],
        }
        body = _encode_json(request_value)
        response = self._request_json("POST", API_PATH, body)
        allowed_members = {
            "createdIds",
            "methodResponses",
            "sessionState",
        }
        if (
            "methodResponses" not in response
            or not set(response).issubset(allowed_members)
        ):
            raise RegistryProtocolError("JMAP response members are invalid")
        if "sessionState" in response:
            _validate_opaque_text(
                response["sessionState"],
                "JMAP session state",
            )
        if "createdIds" in response:
            _validate_created_ids(response["createdIds"])
        method_responses = response.get("methodResponses")
        if type(method_responses) is not list or len(method_responses) != 1:
            raise RegistryProtocolError(
                "JMAP response must contain exactly one method response"
            )
        item = method_responses[0]
        if type(item) is not list or len(item) != 3:
            raise RegistryProtocolError("JMAP method response is malformed")
        response_name, payload, response_call_id = item
        if response_call_id != call_id:
            raise RegistryProtocolError("JMAP call ID does not match")
        if response_name == "error":
            if type(payload) is not dict:
                raise RegistryProtocolError("JMAP method error is malformed")
            error_type = payload.get("type")
            if (
                type(error_type) is not str
                or _ERROR_TYPE.fullmatch(error_type) is None
            ):
                raise RegistryProtocolError("JMAP method error type is invalid")
            raise RegistryMethodError(method, error_type)
        if response_name != method or type(payload) is not dict:
            raise RegistryProtocolError("JMAP method response does not match")
        return payload

    def _create_value(
        self,
        object_type: str,
        value: dict[str, object],
        account_id: str,
    ) -> tuple[str, dict[str, object]]:
        if type(value) is not dict or not value:
            raise ValueError("Registry create must be a non-empty object")
        creation_id = self._next_creation_id()
        payload = self._call(
            f"x:{object_type}/set",
            {
                "accountId": account_id,
                "create": {creation_id: value},
            },
        )
        created = _validate_set_create(
            payload,
            object_type=object_type,
            creation_id=creation_id,
            account_id=account_id,
        )
        return creation_id, created

    def _query_ids(
        self,
        object_type: str,
        *,
        account_id: str,
        filter_value: dict[str, object],
        page_limit: int,
    ) -> tuple[str, ...]:
        _validate_object_type(object_type)
        _validate_id(account_id, "query account ID")
        if (
            type(page_limit) is not int
            or isinstance(page_limit, bool)
            or page_limit < 1
            or page_limit > 100
        ):
            raise ValueError("page limit must be between 1 and 100")
        method = f"x:{object_type}/query"
        payload = self._call(
            method,
            {
                "accountId": account_id,
                "calculateTotal": True,
                "filter": filter_value,
                "limit": page_limit,
                "position": 0,
                "sort": [],
            },
        )
        page_ids, _total, _query_state = _validate_query_page(
            payload,
            account_id=account_id,
            position=0,
            page_limit=page_limit,
        )
        return page_ids

    def _request_json(
        self,
        method: str,
        path: str,
        body: bytes | None,
    ) -> dict[str, object]:
        self._ensure_open()
        connection = None
        response = None
        authorization = None
        primary_in_flight = False
        try:
            authorization = self._credential._authorization_header()
            headers: dict[str, object] = {
                "Accept": "application/json",
                "Authorization": authorization,
            }
            if body is not None:
                headers["Content-Type"] = "application/json"
            connection = http.client.HTTPConnection(
                REGISTRY_HOST,
                REGISTRY_PORT,
                timeout=self._timeout_seconds,
            )
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            if response.status != 200:
                raise RegistryHttpStatusError(response.status)
            response_headers = response.getheaders()
            _validate_content_type(response_headers)
            declared_length = _validate_content_length(response_headers)
            raw = response.read(MAX_JSON_BODY_BYTES + 1)
            if len(raw) > MAX_JSON_BODY_BYTES:
                raise RegistryProtocolError("JSON response exceeds the fixed limit")
            if declared_length is not None and len(raw) != declared_length:
                raise RegistryProtocolError("JSON response length does not match")
            value = _decode_json(raw)
            if type(value) is not dict:
                raise RegistryProtocolError("JSON response must be an object")
            return value
        except RegistryError:
            primary_in_flight = True
            raise
        except (OSError, http.client.HTTPException):
            primary_in_flight = True
            raise RegistryTransportError("loopback HTTP exchange failed") from None
        except BaseException:
            primary_in_flight = True
            raise
        finally:
            cleanup_error: Exception | None = None
            cleanup_cancellation: BaseException | None = None
            cleanup_actions = []
            if authorization is not None:
                def release_authorization() -> None:
                    try:
                        self._credential._release_header(authorization)
                    finally:
                        _wipe(authorization)

                cleanup_actions.append(release_authorization)
            if response is not None:
                cleanup_actions.append(response.close)
            if connection is not None:
                cleanup_actions.append(connection.close)
            for cleanup in cleanup_actions:
                try:
                    cleanup()
                except BaseException as error:
                    if isinstance(error, Exception):
                        if cleanup_error is None:
                            cleanup_error = error
                    elif cleanup_cancellation is None:
                        cleanup_cancellation = error
            if not primary_in_flight:
                if cleanup_cancellation is not None:
                    raise cleanup_cancellation
                if cleanup_error is not None:
                    raise RegistryTransportError(
                        "loopback HTTP resource cleanup failed"
                    ) from None


def _validate_id(value: object, field: str) -> str:
    if type(value) is not str or _SAFE_ID.fullmatch(value) is None:
        raise RegistryProtocolError(f"{field} is invalid")
    return value


def _validate_opaque_text(value: object, field: str) -> str:
    if type(value) is not str:
        raise RegistryProtocolError(f"{field} is malformed")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        raise RegistryProtocolError(f"{field} is malformed") from None
    if not encoded or len(encoded) > MAX_OPAQUE_TEXT_BYTES:
        raise RegistryProtocolError(f"{field} is malformed")
    return value


def _validate_created_ids(value: object) -> None:
    if type(value) is not dict or len(value) > MAX_QUERY_IDS:
        raise RegistryProtocolError("JMAP createdIds is malformed")
    for creation_id, object_id in value.items():
        _validate_opaque_text(creation_id, "JMAP creation ID")
        _validate_opaque_text(object_id, "JMAP created object ID")


def _validate_optional_account_id(
    payload: dict[str, object],
    *,
    account_id: str,
    context: str,
) -> None:
    if "accountId" in payload and payload["accountId"] != account_id:
        raise RegistryProtocolError(f"{context} account does not match")


def _validate_object_type(value: object) -> str:
    if type(value) is not str or _OBJECT_TYPE.fullmatch(value) is None:
        raise ValueError("registry object type is invalid")
    return value


def _validate_credential_type(value: object) -> str:
    if type(value) is not str or value not in _CREDENTIAL_TYPES:
        raise ValueError("credential type must be ApiKey or AppPassword")
    return value


def _validate_properties(
    values: tuple[str, ...] | list[str],
) -> tuple[str, ...]:
    if type(values) not in (tuple, list) or not values or len(values) > 64:
        raise ValueError("Registry properties are invalid")
    result: list[str] = []
    for value in values:
        if type(value) is not str or _PROPERTY.fullmatch(value) is None:
            raise ValueError("Registry property is invalid")
        if value in result:
            raise ValueError("Registry properties contain a duplicate")
        result.append(value)
    return tuple(result)


def _canonical_json_text(value: object) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError, UnicodeError):
        raise RegistryProtocolError(
            "Registry response is not canonicalizable"
        ) from None


def _validate_json_value(
    value: object,
    *,
    depth: int = 0,
) -> None:
    if depth > 64:
        raise ValueError("JSON value is nested too deeply")
    if value is None or type(value) in (str, bool):
        return
    if type(value) is int:
        if value < -(2**63) or value > (2**63 - 1):
            raise ValueError("JSON integer is outside the fixed range")
        return
    if type(value) is list:
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("JSON object key must be text")
            _validate_json_value(item, depth=depth + 1)
        return
    raise ValueError("JSON value contains an unsupported type")


def _encode_json(value: object) -> bytes:
    _validate_json_value(value)
    try:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("JMAP request cannot be encoded") from None
    if len(raw) > MAX_JSON_BODY_BYTES:
        raise ValueError("JMAP request exceeds the fixed body limit")
    return raw


def _validate_set_envelope(
    payload: dict[str, object],
    *,
    account_id: str,
) -> None:
    if not set(payload).issubset(_SET_MEMBERS):
        raise RegistryProtocolError("Registry set response is malformed")
    _validate_optional_account_id(
        payload,
        account_id=account_id,
        context="Registry set",
    )
    for state_member in ("oldState", "newState"):
        if state_member in payload:
            state = payload[state_member]
            if (
                type(state) is not str
                or not state
                or len(state) > 255
                or any(
                    ord(char) < 0x21 or ord(char) > 0x7E
                    for char in state
                )
            ):
                raise RegistryProtocolError(
                    "Registry set state is malformed"
                )


def _empty_set_members(
    payload: dict[str, object],
    *,
    except_members: frozenset[str],
) -> None:
    collection_types: dict[str, type] = {
        "created": dict,
        "destroyed": list,
        "notCreated": dict,
        "notDestroyed": dict,
        "notUpdated": dict,
        "updated": dict,
    }
    for member, expected_type in collection_types.items():
        if member in except_members or member not in payload:
            continue
        value = payload[member]
        if type(value) is not expected_type or value:
            raise RegistryProtocolError(
                "Registry set response contains an unrelated result"
            )


def _set_error(
    errors: object,
    *,
    operation: str,
    object_type: str,
    object_id: str,
) -> RegistrySetError | None:
    if errors is None:
        return None
    if type(errors) is not dict:
        raise RegistryProtocolError("Registry set errors are malformed")
    if not errors:
        return None
    if set(errors) != {object_id}:
        raise RegistryProtocolError("Registry set error target does not match")
    error = errors[object_id]
    if type(error) is not dict:
        raise RegistryProtocolError("Registry set error is malformed")
    error_type = error.get("type")
    if (
        type(error_type) is not str
        or _ERROR_TYPE.fullmatch(error_type) is None
    ):
        raise RegistryProtocolError("Registry set error type is malformed")
    return RegistrySetError(
        operation,
        object_type,
        object_id,
        error_type,
    )


def _validate_set_create(
    payload: dict[str, object],
    *,
    object_type: str,
    creation_id: str,
    account_id: str,
) -> dict[str, object]:
    _validate_set_envelope(payload, account_id=account_id)
    _empty_set_members(
        payload,
        except_members=frozenset({"created", "notCreated"}),
    )
    created = payload.get("created")
    error = _set_error(
        payload.get("notCreated"),
        operation="create",
        object_type=object_type,
        object_id=creation_id,
    )
    if created is not None and (type(created) is not dict):
        raise RegistryProtocolError("Registry created result is malformed")
    if error is not None and created:
        raise RegistryProtocolError(
            "Registry create both succeeded and failed"
        )
    if error is not None:
        raise error
    if type(created) is not dict or set(created) != {creation_id}:
        raise RegistryProtocolError(
            "Registry create result does not match"
        )
    value = created[creation_id]
    if type(value) is not dict:
        raise RegistryProtocolError("Registry created object is malformed")
    return value


def _validate_set_update(
    payload: dict[str, object],
    *,
    object_type: str,
    object_id: str,
    account_id: str,
) -> None:
    _validate_set_envelope(payload, account_id=account_id)
    _empty_set_members(
        payload,
        except_members=frozenset({"updated", "notUpdated"}),
    )
    updated = payload.get("updated")
    error = _set_error(
        payload.get("notUpdated"),
        operation="update",
        object_type=object_type,
        object_id=object_id,
    )
    if error is not None and updated:
        raise RegistryProtocolError(
            "Registry update both succeeded and failed"
        )
    if error is not None:
        raise error
    if type(updated) is not dict or set(updated) != {object_id}:
        raise RegistryProtocolError(
            "Registry update result does not match"
        )
    updated_value = updated[object_id]
    if updated_value is not None and type(updated_value) is not dict:
        raise RegistryProtocolError(
            "Registry update result is malformed"
        )


def _validate_set_destroy(
    payload: dict[str, object],
    *,
    object_type: str,
    object_id: str,
    account_id: str,
) -> None:
    _validate_set_envelope(payload, account_id=account_id)
    _empty_set_members(
        payload,
        except_members=frozenset({"destroyed", "notDestroyed"}),
    )
    destroyed = payload.get("destroyed")
    error = _set_error(
        payload.get("notDestroyed"),
        operation="destroy",
        object_type=object_type,
        object_id=object_id,
    )
    if error is not None and destroyed:
        raise RegistryProtocolError(
            "Registry destroy both succeeded and failed"
        )
    if error is not None:
        raise error
    if type(destroyed) is not list or destroyed != [object_id]:
        raise RegistryProtocolError(
            "Registry destroy result does not match"
        )


def _validate_get_one(
    payload: dict[str, object],
    *,
    object_type: str,
    account_id: str,
    object_id: str,
) -> dict[str, object]:
    allowed = {"accountId", "list", "notFound", "state"}
    required = {"list", "notFound"}
    if not required.issubset(payload) or not set(payload).issubset(allowed):
        raise RegistryProtocolError("Registry get response is malformed")
    _validate_optional_account_id(
        payload,
        account_id=account_id,
        context="Registry get",
    )
    state = payload.get("state")
    if state is not None and (
        type(state) is not str
        or not state
        or len(state) > 255
        or any(ord(char) < 0x21 or ord(char) > 0x7E for char in state)
    ):
        raise RegistryProtocolError("Registry get state is malformed")
    not_found = payload.get("notFound")
    if type(not_found) is not list:
        raise RegistryProtocolError("Registry get notFound is malformed")
    not_found_ids = tuple(
        _validate_id(item, "Registry notFound ID")
        for item in not_found
    )
    values = payload.get("list")
    if type(values) is not list:
        raise RegistryProtocolError("Registry get list is malformed")
    if not_found_ids:
        if not_found_ids == (object_id,) and not values:
            raise RegistryNotFoundError(object_type, object_id)
        raise RegistryProtocolError("Registry notFound does not match")
    if len(values) != 1:
        raise RegistryProtocolError(
            "Registry get must return exactly one object"
        )
    value = values[0]
    if type(value) is not dict or value.get("id") != object_id:
        raise RegistryProtocolError("Registry get object ID does not match")
    return value


def _credential_record(
    credential_type: str,
    account_id: str,
    credential_id: str,
    value: dict[str, object],
) -> CredentialRecord:
    expected = {
        "allowedIps",
        "description",
        "expiresAt",
        "id",
        "permissions",
    }
    if set(value) != expected or value.get("id") != credential_id:
        raise RegistryProtocolError(
            "credential projection is malformed or contains a secret"
        )
    description = value.get("description")
    if (
        type(description) is not str
        or not description
        or len(description) > 1024
        or any(ord(char) < 0x20 for char in description)
    ):
        raise RegistryProtocolError("credential description is malformed")
    expires_at = value.get("expiresAt")
    if expires_at is not None and (
        type(expires_at) is not str
        or not expires_at
        or len(expires_at) > 64
    ):
        raise RegistryProtocolError("credential expiry is malformed")
    permissions = value.get("permissions")
    allowed_ips = value.get("allowedIps")
    if type(permissions) is not dict or type(allowed_ips) is not dict:
        raise RegistryProtocolError("credential metadata is malformed")
    return CredentialRecord(
        credential_type=credential_type,
        credential_id=credential_id,
        account_id=account_id,
        description=description,
        expires_at=expires_at,
        _permissions_json=_canonical_json_text(permissions),
        _allowed_ips_json=_canonical_json_text(allowed_ips),
    )


def _validate_query_page(
    payload: dict[str, object],
    *,
    account_id: str,
    position: int,
    page_limit: int,
) -> tuple[tuple[str, ...], int, str]:
    allowed = {
        "accountId",
        "canCalculateChanges",
        "ids",
        "limit",
        "position",
        "queryState",
        "total",
    }
    required = allowed - {"accountId", "limit"}
    if not required.issubset(payload) or not set(payload).issubset(allowed):
        raise RegistryProtocolError("Registry query response is malformed")
    _validate_optional_account_id(
        payload,
        account_id=account_id,
        context="Registry query",
    )
    if type(payload.get("canCalculateChanges")) is not bool:
        raise RegistryProtocolError(
            "Registry query change capability is malformed"
        )
    response_position = payload.get("position")
    if (
        type(response_position) is not int
        or isinstance(response_position, bool)
        or response_position != 0
        or position != 0
    ):
        raise RegistryProtocolError("Registry query position does not match")
    raw_ids = payload.get("ids")
    if type(raw_ids) is not list or len(raw_ids) > page_limit:
        raise RegistryProtocolError("Registry query IDs are malformed")
    ids = tuple(_validate_id(value, "Registry query ID") for value in raw_ids)
    if len(set(ids)) != len(ids):
        raise RegistryProtocolError("Registry query returned duplicate IDs")
    total = payload.get("total")
    if (
        type(total) is not int
        or isinstance(total, bool)
        or total < 0
        or total != len(ids)
        or total > page_limit
    ):
        raise RegistryProtocolError("Registry query total is malformed")
    query_state = _validate_opaque_text(
        payload.get("queryState"),
        "Registry query state",
    )
    if "limit" in payload:
        response_limit = payload["limit"]
        if (
            type(response_limit) is not int
            or isinstance(response_limit, bool)
            or response_limit < 0
            or response_limit > page_limit
        ):
            raise RegistryProtocolError("Registry query limit is malformed")
    return ids, total, query_state


def _validate_content_type(headers: list[tuple[str, str]]) -> None:
    content_types = [
        value for name, value in headers if name.lower() == "content-type"
    ]
    if len(content_types) != 1:
        raise RegistryProtocolError("response Content-Type is invalid")
    parts = [part.strip().lower() for part in content_types[0].split(";")]
    if (
        parts[0] != "application/json"
        or len(parts) > 2
        or any(part != "charset=utf-8" for part in parts[1:])
    ):
        raise RegistryProtocolError("response Content-Type is invalid")


def _validate_content_length(
    headers: list[tuple[str, str]],
) -> int | None:
    values = [
        value.strip()
        for name, value in headers
        if name.lower() == "content-length"
    ]
    if not values:
        return None
    if len(values) != 1 or not values[0].isascii() or not values[0].isdigit():
        raise RegistryProtocolError("response Content-Length is invalid")
    try:
        declared = int(values[0], 10)
    except (ValueError, OverflowError):
        raise RegistryProtocolError(
            "response Content-Length is invalid"
        ) from None
    if declared > MAX_JSON_BODY_BYTES:
        raise RegistryProtocolError("JSON response exceeds the fixed limit")
    return declared


def _reject_float(_value: str):
    raise ValueError("floating-point JSON is not allowed")


def _reject_constant(_value: str):
    raise ValueError("non-finite JSON is not allowed")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _decode_json(raw: bytes) -> object:
    try:
        text = raw.decode("utf-8", "strict")
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise RegistryProtocolError("response is not valid strict JSON") from None


def _validate_session(
    payload: dict[str, object],
    *,
    expected_username: str,
    expected_account_id: str | None,
) -> RegistrySession:
    username = payload.get("username")
    if username != expected_username:
        raise RegistryProtocolError("JMAP session username does not match")
    if payload.get("apiUrl") != API_URL:
        raise RegistryProtocolError("JMAP session API URL does not match")

    capabilities = payload.get("capabilities")
    if (
        type(capabilities) is not dict
        or type(capabilities.get(CORE_CAPABILITY)) is not dict
        or type(capabilities.get(STALWART_CAPABILITY)) is not dict
    ):
        raise RegistryProtocolError("JMAP session capabilities are incomplete")

    primary_accounts = payload.get("primaryAccounts")
    if type(primary_accounts) is not dict:
        raise RegistryProtocolError("JMAP primary accounts are malformed")
    account_id = _validate_id(
        primary_accounts.get(STALWART_CAPABILITY),
        "JMAP primary account ID",
    )
    if expected_account_id is not None and account_id != expected_account_id:
        raise RegistryProtocolError("JMAP primary account does not match")

    accounts = payload.get("accounts")
    if type(accounts) is not dict:
        raise RegistryProtocolError("JMAP accounts are malformed")
    account = accounts.get(account_id)
    if type(account) is not dict or account.get("name") != expected_username:
        raise RegistryProtocolError("JMAP primary account identity does not match")
    account_capabilities = account.get("accountCapabilities")
    if (
        type(account_capabilities) is not dict
        or type(account_capabilities.get(STALWART_CAPABILITY)) is not dict
    ):
        raise RegistryProtocolError(
            "JMAP primary account lacks Registry capability"
        )

    return RegistrySession(
        username=expected_username,
        account_id=account_id,
    )
