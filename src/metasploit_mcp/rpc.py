"""MessagePack transport. Mutating calls are never replayed automatically."""
import asyncio
import base64
import math
import re
import ssl
from typing import Any

import httpx
import msgpack

from .config import Config


class RPCError(Exception):
    """Expected connection, authentication, or Metasploit error."""

    def __init__(self, message: str, *, authentication: bool = False):
        super().__init__(message)
        self.authentication = authentication


def decode_input(value: Any) -> Any:
    """Decode bytes and typed/escaped maps without reserving any literal map key."""
    if isinstance(value, dict):
        if set(value) == {"$binary"}:
            try:
                return base64.b64decode(value["$binary"], validate=True)
            except (ValueError, TypeError) as exc:
                raise RPCError("Invalid $binary base64 input") from exc
        if set(value) == {"$map"}:
            entries = value["$map"]
            if not isinstance(entries, list):
                raise RPCError("$map must contain an array of [key, value] pairs")
            result = {}
            for entry in entries:
                if not isinstance(entry, list) or len(entry) != 2:
                    raise RPCError("$map entries must be [key, value] pairs")
                key, item = (decode_input(part) for part in entry)
                try:
                    if key in result:
                        raise RPCError("Duplicate $map key; no data was sent")
                    result[key] = item
                except TypeError as exc:
                    raise RPCError("$map keys must decode to hashable scalar values") from exc
            return result
        return {k: decode_input(v) for k, v in value.items()}
    if isinstance(value, list):
        return [decode_input(v) for v in value]
    return value


def json_output(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"$binary": base64.b64encode(value).decode("ascii")}
    if isinstance(value, dict):
        # JSON object keys cannot retain numeric/binary key types. A pair list
        # preserves them and also escapes literal objects shaped like a marker.
        if any(not isinstance(key, str) for key in value) or set(value) in ({"$binary"}, {"$map"}):
            return {"$map": [[json_output(key), json_output(item)] for key, item in value.items()]}
        return {key: json_output(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_output(v) for v in value]
    return value


def legacy_output(value: Any) -> Any:
    """Recover raw Ruby string bytes without changing MessagePack bin fields."""
    if isinstance(value, str):
        try:
            value.encode("utf-8")
            return value
        except UnicodeEncodeError:
            return value.encode("utf-8", errors="surrogateescape")
    if isinstance(value, dict):
        return {legacy_output(k): legacy_output(v) for k, v in value.items()}
    if isinstance(value, list):
        return [legacy_output(v) for v in value]
    return value


class RPCClient:
    def __init__(self, config: Config, transport: httpx.AsyncBaseTransport | None = None):
        self.config = config
        self._token = config.token
        self._lock = asyncio.Lock()
        verify: bool | ssl.SSLContext = config.verify_tls
        if config.ca_file:
            verify = ssl.create_default_context(cafile=config.ca_file)
        self._http = httpx.AsyncClient(
            verify=verify, timeout=config.timeout, transport=transport,
            trust_env=False, follow_redirects=False,
        )

    async def close(self):
        await self._http.aclose()

    def _redact(self, text: str) -> str:
        for secret in (self.config.password, self.config.token, self._token):
            if secret:
                text = text.replace(secret, "[redacted]")
        return text

    async def _request(self, parts: list[Any], timeout: float | None = None) -> Any:
        try:
            body = msgpack.packb(parts, use_bin_type=True)
        except (ValueError, TypeError, OverflowError) as exc:
            raise RPCError("Arguments cannot be encoded as MessagePack") from exc
        try:
            async with self._http.stream(
                "POST", self.config.url, content=body,
                headers={"Content-Type": "binary/message-pack"},
                timeout=self.config.timeout if timeout is None else timeout,
            ) as response:
                status = response.status_code
                chunks = bytearray()
                async for chunk in response.aiter_bytes():
                    chunks.extend(chunk)
                    if len(chunks) > self.config.max_response_bytes:
                        raise RPCError("RPC response exceeds the configured byte limit; result was not replayed")
        except httpx.TimeoutException as exc:
            raise RPCError(
                f"RPC timed out ({type(exc).__name__}). The action may still be running; inspect jobs/sessions/console "
                "before repeating it. No request was replayed."
            ) from exc
        except httpx.HTTPError as exc:
            raise RPCError(
                "RPC connection failed; check daemon, URL, and TLS settings. "
                "An in-flight action may have run. No request was replayed."
            ) from exc
        try:
            result = legacy_output(msgpack.unpackb(
                chunks, raw=False, strict_map_key=False, unicode_errors="surrogateescape",
            ))
        except (ValueError, TypeError, msgpack.UnpackException) as exc:
            if status != 200:
                raise RPCError(
                    f"RPC HTTP status {status}; check endpoint and daemon",
                    authentication=status == 401,
                ) from exc
            raise RPCError("RPC returned invalid MessagePack; check the endpoint") from exc
        if isinstance(result, dict) and result.get("error"):
            code = result.get("error_code", status)
            # Modern Metasploit uses error_message; older services use error_string.
            message = self._redact(str(result.get(
                "error_message", result.get("error_string", "RPC request failed"),
            )))
            raise RPCError(
                f"Metasploit RPC error {code}: {message}",
                authentication=status == 401 or str(code) == "401",
            )
        if status != 200:
            raise RPCError(
                f"RPC HTTP status {status}; check endpoint and daemon", authentication=status == 401,
            )
        if isinstance(result, dict) and result.get("result") == "failure":
            raise RPCError("Metasploit returned failure; check method arguments and object IDs")
        return result

    async def call(
        self, method: str, params: list[Any] | None = None, *,
        authenticated: bool | None = None, timeout: float | None = None,
    ) -> Any:
        if not re.fullmatch(r"[^.\s]+\.[^\s]+", method):
            raise RPCError("Use a method name such as core.version or module.info")
        if timeout is not None and (not math.isfinite(timeout) or timeout <= 0):
            raise RPCError("RPC timeout must be a positive finite number")
        arguments = decode_input(params or [])
        if authenticated is None:
            authenticated = method not in {"auth.login", "health.check"}
        token = None
        if authenticated:
            # Only login is serialized. A long-running call must not block a
            # second call that reads state, interrupts a session, or stops a job.
            async with self._lock:
                if not self._token:
                    if not self.config.password:
                        raise RPCError("Set MSF_RPC_PASS or MSF_RPC_TOKEN before calling Metasploit")
                    login = await self._request([
                        "auth.login", self.config.username, self.config.password,
                    ], timeout)
                    if (not isinstance(login, dict) or login.get("result") != "success"
                            or not isinstance(login.get("token"), str)):
                        raise RPCError("RPC login failed")
                    self._token = login["token"]
                token = self._token
        try:
            result = await self._request(
                [method, *([token] if authenticated else []), *arguments], timeout,
            )
        except RPCError as exc:
            if exc.authentication and token is not None:
                async with self._lock:
                    if self._token == token:
                        self._token = self.config.token
            raise
        if method == "auth.login" and isinstance(result, dict) and result.get("result") == "success":
            async with self._lock:
                self._token = result["token"]
        elif method == "auth.logout":
            async with self._lock:
                if self._token == token:
                    self._token = self.config.token
        return json_output(result)
