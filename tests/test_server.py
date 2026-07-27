"""Tests for error surfacing, feature flags, and the CLI entrypoint."""

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from leakix_mcp import server
from leakix_mcp.errors import LeakixAPIError
from leakix_mcp.features import HTTP_TRANSPORT
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
    from pydantic import ValidationError

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
