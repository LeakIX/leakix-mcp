"""LeakIX MCP Server implementation."""

import json
import os
import sys
from typing import Any

from leakix import AsyncClient
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .tools import dispatch, get_tools

server = Server("leakix-mcp")

_client: AsyncClient | None = None


def get_client() -> AsyncClient:
    """Get or create the LeakIX client."""
    global _client
    if _client is None:
        api_key = os.environ.get("LEAKIX_API_KEY", "")
        if not api_key:
            raise ValueError(
                "LEAKIX_API_KEY environment variable is required. "
                "Get your API key from https://leakix.net/settings"
            )
        _client = AsyncClient(api_key=api_key)
    return _client


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


async def run_server() -> None:
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main() -> None:
    """Entry point for the server."""
    import asyncio

    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Server error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
