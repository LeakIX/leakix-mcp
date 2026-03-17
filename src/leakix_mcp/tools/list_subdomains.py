"""Enumerate subdomains for a domain on LeakIX."""

from typing import Any

from leakix import AsyncClient
from mcp.types import Tool

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


async def handle(client: AsyncClient, arguments: dict[str, Any]) -> Any:
    """Handle list_subdomains tool call."""
    domain = arguments["domain"]
    r = await client.get_subdomains(domain)
    return r.json() if r.is_success() else []
