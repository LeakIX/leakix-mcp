"""HTTP transport."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import uvicorn
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount
from starlette.types import ASGIApp, Receive, Scope, Send

from .common import _api_key, server


class ApiKeyMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        key = request.headers.get("x-api-key", "")
        if not key:
            response = JSONResponse(
                {"error": "x-api-key header is required"},
                status_code=401,
            )
            await response(scope, receive, send)
            return

        _api_key.set(key)
        await self.app(scope, receive, send)


def parse_address(address: str) -> tuple[str, int]:
    """Parse a server address like '0.0.0.0:8080' or ':8081'."""
    host, sep, port_str = address.rpartition(":")
    if not sep or not port_str:
        raise ValueError(
            f"Invalid address format: {address!r} (expected host:port)"
        )
    port = int(port_str)
    if not 0 < port < 65536:
        raise ValueError(f"Port must be between 1 and 65535, got {port}")
    return host or "0.0.0.0", port


def run_http(host: str, port: int) -> None:
    """Run the MCP server over Streamable HTTP."""
    session_manager = StreamableHTTPSessionManager(app=server)

    @asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncGenerator[None]:
        async with session_manager.run():
            yield

    app = Starlette(
        routes=[Mount("/mcp", app=session_manager.handle_request)],
        middleware=[Middleware(ApiKeyMiddleware)],
        lifespan=lifespan,
    )

    uvicorn.run(app, host=host, port=port)
