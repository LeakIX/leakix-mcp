"""Look up a specific IP address on LeakIX."""

from typing import Any

from mcp.types import Tool

from ..client import LeakIXClient

TOOL = Tool(
    name="host_lookup",
    description=(
        "Get detailed information about a specific IP address. "
        "Returns all known services and data leaks associated with "
        "the IP, including open ports, software versions, SSL "
        "certificates, and any exposed data."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "ip": {
                "type": "string",
                "description": "IPv4 or IPv6 address to lookup.",
            },
        },
        "required": ["ip"],
    },
)


async def handle(client: LeakIXClient, arguments: dict[str, Any]) -> Any:
    """Handle host_lookup tool call."""
    ip = arguments["ip"]
    r = await client.api.get_host(ip)
    return r.json() if r.is_success() else {}
