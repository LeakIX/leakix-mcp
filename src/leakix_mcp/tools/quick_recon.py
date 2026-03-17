"""Quick reconnaissance on a target IP or domain."""

from typing import Any

from mcp.types import Tool

from ..client import LeakIXClient

TOOL = Tool(
    name="quick_recon",
    description=(
        "Quick reconnaissance on a target IP or domain. "
        "Automatically detects target type and performs: "
        "- For IPs: host lookup with services and leaks "
        "- For domains: domain lookup + subdomain enumeration "
        "Use this for fast initial assessment of a target."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": ("IP address or domain name to investigate."),
            },
        },
        "required": ["target"],
    },
)


async def handle(client: LeakIXClient, arguments: dict[str, Any]) -> Any:
    """Handle quick_recon tool call."""
    target = arguments["target"]
    return await client.quick_recon(target)
