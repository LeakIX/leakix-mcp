"""LeakIX MCP Server implementation."""

import argparse
import json
import os
import sys
from contextvars import ContextVar
from typing import Any

from leakix import AsyncClient
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .tools import dispatch, get_tools

server = Server("leakix-mcp")

_api_key: ContextVar[str] = ContextVar("api_key")


def get_client() -> AsyncClient:
    """Create a LeakIX client using the current API key."""
    try:
        key = _api_key.get()
    except LookupError:
        raise ValueError(
            "No API key provided. Set LEAKIX_API_KEY (stdio) "
            "or pass x-api-key header (HTTP)."
        ) from None
    return AsyncClient(api_key=key)


def serialize_object(obj: Any) -> Any:
    """Serialize objects to dicts for JSON encoding."""
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    return str(obj)


def format_result(data: Any) -> str:
    """Format result data as JSON string."""
    if isinstance(data, list):
        data = [
            item.to_dict() if hasattr(item, "to_dict") else item
            for item in data
        ]
    elif isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list):
                data[key] = [
                    item.to_dict() if hasattr(item, "to_dict") else item
                    for item in value
                ]
    return json.dumps(data, indent=2, default=serialize_object)


@server.list_tools()  # type: ignore[no-untyped-call,untyped-decorator]
async def list_tools() -> list[Tool]:
    """List available LeakIX tools."""
    return get_tools()


@server.call_tool()  # type: ignore[untyped-decorator]
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Execute a LeakIX tool."""
    client = get_client()

    try:
        result = await dispatch(client, name, arguments)
        if result is None:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
        return [TextContent(type="text", text=format_result(result))]
    except ValueError as e:
        return [TextContent(type="text", text=f"Configuration error: {e}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {e}")]


async def run_stdio() -> None:
    """Run the MCP server over stdio."""
    api_key = os.environ.get("LEAKIX_API_KEY", "")
    if not api_key:
        raise ValueError(
            "LEAKIX_API_KEY environment variable is required. "
            "Get your API key from https://leakix.net/settings"
        )
    _api_key.set(api_key)

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def parse_address(address: str) -> tuple[str, int]:
    """Parse a server address like '0.0.0.0:8080' or ':8081'."""
    host, _, port_str = address.rpartition(":")
    if not port_str:
        raise ValueError(
            f"Invalid address format: {address!r} (expected host:port)"
        )
    return host or "0.0.0.0", int(port_str)


def run_http(host: str, port: int) -> None:
    """Run the MCP server over Streamable HTTP."""
    from collections.abc import AsyncIterator
    from contextlib import asynccontextmanager

    import uvicorn
    from mcp.server.streamable_http_manager import (
        StreamableHTTPSessionManager,
    )
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.middleware.base import (
        BaseHTTPMiddleware,
        RequestResponseEndpoint,
    )
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
    from starlette.routing import Mount

    class ApiKeyMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> Response:
            key = request.headers.get("x-api-key", "")
            if not key:
                return JSONResponse(
                    {"error": "x-api-key header is required"},
                    status_code=401,
                )
            _api_key.set(key)
            return await call_next(request)

    session_manager = StreamableHTTPSessionManager(app=server)

    @asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            yield

    app = Starlette(
        routes=[Mount("/mcp", app=session_manager.handle_request)],
        middleware=[Middleware(ApiKeyMiddleware)],
        lifespan=lifespan,
    )

    uvicorn.run(app, host=host, port=port)


def main() -> None:
    """Entry point for the server."""
    import asyncio

    parser = argparse.ArgumentParser(description="LeakIX MCP Server")
    parser.add_argument(
        "--server-address",
        default=None,
        help="Listen address for HTTP transport "
        "(e.g. '0.0.0.0:8080' or ':8081'). "
        "Defaults to stdio transport if not set.",
    )
    args = parser.parse_args()

    try:
        if args.server_address:
            host, port = parse_address(args.server_address)
            run_http(host, port)
        else:
            asyncio.run(run_stdio())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Server error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
