"""Tests for error surfacing, feature flags, and the CLI entrypoint."""

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from leakix import AsyncClient
from pydantic import ValidationError

from leakix_mcp import server
from leakix_mcp.errors import LeakixAPIError
from leakix_mcp.features import HTTP_TRANSPORT
from leakix_mcp.server import ApiKeyMiddleware
from leakix_mcp.tools import host_lookup
from leakix_mcp.tools.helpers import unwrap


def _response(*, success: bool, status: int, data: Any) -> Any:
    resp = MagicMock()
    resp.is_success.return_value = success
    resp.status_code.return_value = status
    resp.json.return_value = data
    return resp


def test_unwrap_returns_json_on_success() -> None:
    assert unwrap(_response(success=True, status=200, data={"a": 1})) == {
        "a": 1
    }


def test_unwrap_raises_on_failure() -> None:
    resp = _response(success=False, status=429, data={"error": "rate limited"})
    with pytest.raises(LeakixAPIError) as info:
        unwrap(resp)
    assert info.value.status_code == 429
    assert "rate limited" in str(info.value)


@pytest.mark.asyncio
async def test_api_failure_propagates_through_handler() -> None:
    """A failed API call surfaces as an error, not an empty result."""
    client = MagicMock()
    client.get_host = AsyncMock(
        return_value=_response(success=False, status=500, data=None)
    )
    with pytest.raises(LeakixAPIError):
        await host_lookup.handle(client, {"ip": "1.2.3.4"})


@pytest.mark.asyncio
async def test_host_lookup_rejects_non_ip() -> None:
    client = MagicMock()
    with pytest.raises(ValidationError):
        await host_lookup.handle(client, {"ip": "example.com"})


class TestFeatureFlag:
    def test_http_transport_off_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(HTTP_TRANSPORT.env_var, raising=False)
        assert HTTP_TRANSPORT.enabled() is False

    @pytest.mark.parametrize("value", ["1", "true", "YES", "on"])
    def test_http_transport_enabled(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv(HTTP_TRANSPORT.env_var, value)
        assert HTTP_TRANSPORT.enabled() is True

    def test_main_refuses_http_when_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(HTTP_TRANSPORT.env_var, raising=False)
        monkeypatch.setattr(
            "sys.argv", ["leakix-mcp", "--server-address", ":8080"]
        )
        with pytest.raises(SystemExit) as info:
            server.main()
        assert info.value.code == 2


class TestGetClient:
    def test_returns_client_when_key_set(self) -> None:
        token = server._api_key.set("secret-key")
        try:
            assert isinstance(server.get_client(), AsyncClient)
        finally:
            server._api_key.reset(token)

    def test_raises_without_key(self) -> None:
        with pytest.raises(ValueError, match="No API key"):
            server.get_client()


class TestSerialization:
    def test_serialize_uses_to_dict(self) -> None:
        obj = MagicMock()
        obj.to_dict.return_value = {"a": 1}
        assert server._serialize(obj) == {"a": 1}

    def test_serialize_falls_back_to_str(self) -> None:
        assert server._serialize(object()).startswith("<object")

    def test_format_result_is_json(self) -> None:
        assert (
            server.format_result({"b": [1, 2]})
            == '{\n  "b": [\n    1,\n    2\n  ]\n}'
        )


async def _collect(scope: dict[str, Any]) -> tuple[list[Any], list[Any]]:
    """Drive ApiKeyMiddleware and capture (downstream-scopes, sent-messages)."""
    seen: list[Any] = []
    sent: list[Any] = []

    async def app(s: Any, receive: Any, send: Any) -> None:
        seen.append(s)

    async def send(message: Any) -> None:
        sent.append(message)

    async def receive() -> Any:
        return {}

    await ApiKeyMiddleware(app)(scope, receive, send)
    return seen, sent


class TestApiKeyMiddleware:
    async def test_rejects_missing_key(self) -> None:
        seen, sent = await _collect({"type": "http", "headers": []})
        assert seen == []
        assert any(
            m.get("type") == "http.response.start" and m["status"] == 401
            for m in sent
        )

    async def test_sets_key_and_forwards(self) -> None:
        scope = {"type": "http", "headers": [(b"x-api-key", b"secret")]}
        seen, _ = await _collect(scope)
        assert len(seen) == 1

    async def test_passes_non_http_through(self) -> None:
        seen, _ = await _collect({"type": "lifespan"})
        assert seen == [{"type": "lifespan"}]


async def test_run_stdio_requires_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LEAKIX_API_KEY", raising=False)
    with pytest.raises(ValueError, match="LEAKIX_API_KEY"):
        await server.run_stdio()
