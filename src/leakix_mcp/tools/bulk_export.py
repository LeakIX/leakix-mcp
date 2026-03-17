"""Bulk export leak data from LeakIX."""

from typing import Any

from leakix import RawQuery
from mcp.types import Tool

from ..client import LeakIXClient

TOOL = Tool(
    name="bulk_export",
    description=(
        "Bulk export leak data (requires Pro API). "
        "Returns aggregated results for large-scale analysis. "
        "Use this for exporting large datasets efficiently. "
        "Results include grouped events by target."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": (
                    "Search query. Examples: "
                    "'+plugin:GitConfigHttpPlugin', "
                    "'+country:FR +plugin:MongoOpenPlugin'"
                ),
            },
        },
        "required": ["query"],
    },
)


async def handle(client: LeakIXClient, arguments: dict[str, Any]) -> Any:
    """Handle bulk_export tool call."""
    query = arguments["query"]
    r = await client.api.bulk_export(queries=[RawQuery(query)])
    return r.json() if r.is_success() else []
