"""Search LeakIX for exposed services."""

from typing import Any

from leakix import AsyncClient, Scope
from mcp.types import Tool

TOOL = Tool(
    name="search_services",
    description=(
        "Search LeakIX for exposed services (open ports, software, "
        'protocols). Use query syntax like \'+country:"France" '
        "+port:22' or '+plugin:OpenSSH'. Returns detailed service "
        "info including IP, port, software, geolocation, network."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": (
                    "Search query. Examples: '+country:\"US\"', "
                    "'+port:3306', '+plugin:MySQL', "
                    "'+ip:192.168.0.0/16', '+host:example.com'"
                ),
            },
            "page": {
                "type": "integer",
                "description": "Page number (0-indexed). Default: 0",
                "default": 0,
            },
        },
        "required": ["query"],
    },
)


async def handle(client: AsyncClient, arguments: dict[str, Any]) -> Any:
    """Handle search_services tool call."""
    query = arguments["query"]
    page = arguments.get("page", 0)
    r = await client.search(query, scope=Scope.SERVICE, page=page)
    return r.json() if r.is_success() else []
