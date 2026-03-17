"""Look up a specific domain on LeakIX."""

from typing import Any

from leakix import AsyncClient
from mcp.types import Tool

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


async def handle(client: AsyncClient, arguments: dict[str, Any]) -> Any:
    """Handle domain_lookup tool call."""
    domain = arguments["domain"]
    r = await client.get_domain(domain)
    return r.json() if r.is_success() else {}
