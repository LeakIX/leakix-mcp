"""Generate a security exposure report for a target."""

from typing import Any

from mcp.types import Tool

from ..client import LeakIXClient

TOOL = Tool(
    name="exposure_report",
    description=(
        "Generate a comprehensive security exposure report. "
        "Analyzes a target and returns: risk level, "
        "critical findings, exposed ports, technologies, "
        "leak summary, and recommendations. "
        "Perfect for security assessments."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "IP address or domain to analyze.",
            },
        },
        "required": ["target"],
    },
)


async def handle(client: LeakIXClient, arguments: dict[str, Any]) -> Any:
    """Handle exposure_report tool call."""
    target = arguments["target"]
    return await client.exposure_report(target)
