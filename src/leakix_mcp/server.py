"""LeakIX MCP Server implementation."""

import argparse
import asyncio
import json
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Any

import uvicorn
from leakix import AsyncClient
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.server.streamable_http_manager import (
    StreamableHTTPSessionManager,
)
from mcp.shared.exceptions import MCPError
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListResourcesResult,
    ListToolsResult,
    PaginatedRequestParams,
    ReadResourceRequestParams,
    ReadResourceResult,
    TextContent,
    TextResourceContents,
)
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Mount
from starlette.types import ASGIApp, Receive, Scope, Send

from .address import AddressError, parse_address
from .features import HTTP_TRANSPORT
from .resources import get_resource, get_resources, read_resource
from .tools import dispatch, get_tools

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


def _serialize(obj: Any) -> Any:
    """JSON default: use to_dict() when available, else str()."""
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    return str(obj)


def format_result(data: Any) -> str:
    """Format result data as a JSON string (without mutating it)."""
    return json.dumps(data, indent=2, default=_serialize)


async def list_tools(
    _ctx: ServerRequestContext[Any], _params: PaginatedRequestParams | None
) -> ListToolsResult:
    """List available LeakIX tools."""
    return ListToolsResult(tools=get_tools())


async def list_resources(
    _ctx: ServerRequestContext[Any], _params: PaginatedRequestParams | None
) -> ListResourcesResult:
    """List available LeakIX resources."""
    return ListResourcesResult(resources=get_resources())


async def handle_read_resource(
    _ctx: ServerRequestContext[Any], params: ReadResourceRequestParams
) -> ReadResourceResult:
    """Read a LeakIX resource by URI."""
    uri = str(params.uri)
    content = await read_resource(uri)
    if content is None:
        raise ValueError(f"Unknown resource: {params.uri}")
    resource = get_resource(uri)
    return ReadResourceResult(
        contents=[
            TextResourceContents(
                uri=params.uri,
                mime_type=resource.mime_type if resource else None,
                text=content,
            )
        ]
    )


async def call_tool(
    _ctx: ServerRequestContext[Any], params: CallToolRequestParams
) -> CallToolResult:
    """Execute a LeakIX tool.

    Failures are returned as an error result (isError=True) rather than a
    successful reply, so a failure is never mistaken for an empty answer.
    The low-level server hands the handler the raw params, so this does the
    exception-to-error-result conversion the SDK used to do for us.
    """
    try:
        client = get_client()
        result = await dispatch(client, params.name, params.arguments or {})
        if result is None:
            raise ValueError(f"Unknown tool: {params.name}")
        return CallToolResult(
            content=[TextContent(type="text", text=format_result(result))]
        )
    except MCPError:
        raise
    except Exception as e:
        return CallToolResult(
            content=[TextContent(type="text", text=str(e))], is_error=True
        )


server = Server(
    "leakix-mcp",
    on_list_tools=list_tools,
    on_list_resources=list_resources,
    on_read_resource=handle_read_resource,
    on_call_tool=call_tool,
)


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


class ApiKeyMiddleware:
    """Pure-ASGI middleware that requires and stores the API key.

    Running as pure ASGI (rather than BaseHTTPMiddleware) keeps the key on
    the same context as the downstream handler, so get_client() sees it.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope["headers"])
        key = headers.get(b"x-api-key", b"").decode()
        if not key:
            response = JSONResponse(
                {"error": "x-api-key header is required"}, status_code=401
            )
            await response(scope, receive, send)
            return
        _api_key.set(key)
        await self.app(scope, receive, send)


def run_http(host: str, port: int) -> None:
    """Run the MCP server over Streamable HTTP."""
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

    parser = argparse.ArgumentParser(description="LeakIX MCP Server")
    parser.add_argument(
        "--server-address",
        default=None,
        help="Listen address for the experimental HTTP transport "
        "(e.g. '0.0.0.0:8080' or ':8081'), gated behind "
        f"{HTTP_TRANSPORT.env_var}=1. Defaults to stdio transport.",
    )
    args = parser.parse_args()

    try:
        if args.server_address:
            if not HTTP_TRANSPORT.enabled():
                parser.error(
                    "HTTP transport is experimental and disabled. "
                    f"Set {HTTP_TRANSPORT.env_var}=1 to enable it."
                )
            try:
                address = parse_address(args.server_address)
            except AddressError as e:
                parser.error(str(e))
            run_http(str(address.host), address.port)
        else:
            asyncio.run(run_stdio())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Server error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
