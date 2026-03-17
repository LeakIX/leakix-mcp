"""Look up a specific domain on LeakIX."""

from typing import Any

from mcp.types import Tool

from ..client import LeakIXClient

TOOL = Tool(
    name="domain_lookup",
    description=(
        "Get information about a specific domain. "
        "Returns services and data leaks associated with the domain "
        "and its subdomains, including exposed services, "
        "certificates, and potential security issues."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": "Domain name (e.g., 'example.com').",
            },
        },
        "required": ["domain"],
    },
)


async def handle(client: LeakIXClient, arguments: dict[str, Any]) -> Any:
    """Handle domain_lookup tool call."""
    domain = arguments["domain"]
    r = await client.api.get_domain(domain)
    return r.json() if r.is_success() else {}
