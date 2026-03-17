"""Enumerate subdomains for a domain on LeakIX."""

from typing import Any

from mcp.types import Tool

from ..client import LeakIXClient

TOOL = Tool(
    name="list_subdomains",
    description=(
        "Enumerate discovered subdomains for a domain. "
        "Returns a list of subdomains found through various "
        "discovery methods."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": "Domain name to enumerate subdomains.",
            },
        },
        "required": ["domain"],
    },
)


async def handle(client: LeakIXClient, arguments: dict[str, Any]) -> Any:
    """Handle list_subdomains tool call."""
    domain = arguments["domain"]
    r = await client.api.get_subdomains(domain)
    return r.json() if r.is_success() else []
