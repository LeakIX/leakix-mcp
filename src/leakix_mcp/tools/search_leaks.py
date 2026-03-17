"""Search LeakIX for data leaks."""

from typing import Any

from leakix import AsyncClient, Scope
from mcp.types import Tool

TOOL = Tool(
    name="search_leaks",
    description=(
        "Search LeakIX for data leaks and exposed databases. "
        "Returns information about leaked credentials, exposed "
        "databases, and data breaches. Use queries like "
        "'+leak.severity:critical' or '+leak.dataset.infected:true'."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": (
                    "Search query. Examples: "
                    "'+leak.severity:critical', "
                    "'+leak.dataset.rows:>1000', "
                    "'+plugin:GitConfigHttpPlugin'"
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
    """Handle search_leaks tool call."""
    query = arguments["query"]
    page = arguments.get("page", 0)
    r = await client.search(query, scope=Scope.LEAK, page=page)
    return r.json() if r.is_success() else []
