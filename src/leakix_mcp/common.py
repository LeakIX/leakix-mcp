"""Common server components."""

import json
from contextvars import ContextVar
from typing import Any

from leakix import AsyncClient
from mcp.server import Server
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
