"""Tests for HTTP transport API key isolation."""

import asyncio

import httpx
import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route

from leakix_mcp.common import _api_key
from leakix_mcp.http import ApiKeyMiddleware, parse_address


async def echo_key(request: httpx.Request) -> JSONResponse:
    try:
        key = _api_key.get()
    except LookupError:
        key = None
    return JSONResponse({"api_key": key})


@pytest.fixture
def app() -> Starlette:
    return Starlette(
        routes=[Route("/echo", echo_key)],
        middleware=[Middleware(ApiKeyMiddleware)],
    )


class TestApiKeyMiddleware:
    @pytest.mark.asyncio
    async def test_missing_key_returns_401(self, app: Starlette) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/echo")
            assert resp.status_code == 401
            assert resp.json() == {"error": "x-api-key header is required"}

    @pytest.mark.asyncio
    async def test_key_is_set_in_context(self, app: Starlette) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/echo", headers={"x-api-key": "secret-1"})
            assert resp.status_code == 200
            assert resp.json() == {"api_key": "secret-1"}

    @pytest.mark.asyncio
    async def test_concurrent_requests_isolated(
        self, app: Starlette
    ) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            keys = [f"key-{i}" for i in range(20)]

            async def fetch(key: str) -> str | None:
                resp = await client.get("/echo", headers={"x-api-key": key})
                data: dict[str, str | None] = resp.json()
                return data["api_key"]

            results = await asyncio.gather(*(fetch(k) for k in keys))
            assert results == keys


class TestParseAddress:
    def test_host_and_port(self) -> None:
        assert parse_address("127.0.0.1:8080") == ("127.0.0.1", 8080)

    def test_port_only_defaults_host(self) -> None:
        assert parse_address(":9090") == ("0.0.0.0", 9090)

    def test_hostname(self) -> None:
        assert parse_address("localhost:3000") == ("localhost", 3000)

    def test_invalid_format(self) -> None:
        with pytest.raises(ValueError, match="Invalid address format"):
            parse_address("no-port-here")

    def test_port_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="Port must be between"):
            parse_address(":99999")

    def test_port_zero(self) -> None:
        with pytest.raises(ValueError, match="Port must be between"):
            parse_address(":0")
