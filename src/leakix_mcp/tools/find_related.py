"""Find targets related to a given IP or domain."""

from typing import Any

from mcp.types import Tool

from ..client import LeakIXClient

TOOL = Tool(
    name="find_related",
    description=(
        "Find targets related to a given IP or domain. "
        "Discovers similar targets based on shared "
        "characteristics like technology stack, ASN, "
        "or network range. Useful for attack surface mapping."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": ("IP address or domain to find relations for."),
            },
            "relation_type": {
                "type": "string",
                "enum": ["technology", "asn", "network"],
                "description": (
                    "Type of relation to search for. "
                    "technology: same software stack, "
                    "asn: same autonomous system, "
                    "network: same network range. "
                    "Default: technology"
                ),
                "default": "technology",
            },
        },
        "required": ["target"],
    },
)


async def handle(client: LeakIXClient, arguments: dict[str, Any]) -> Any:
    """Handle find_related tool call."""
    target = arguments["target"]
    relation_type = arguments.get("relation_type", "technology")
    return await client.find_related(target, relation_type)
