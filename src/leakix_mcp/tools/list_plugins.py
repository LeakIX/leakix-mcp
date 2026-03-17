"""List available LeakIX detection plugins."""

from typing import Any

from mcp.types import Tool

from ..client import LeakIXClient

TOOL = Tool(
    name="list_plugins",
    description=(
        "Get the list of available LeakIX detection plugins. "
        "Plugins identify specific services, software, and "
        "vulnerabilities. Use plugin names in search queries "
        "with '+plugin:PluginName'."
    ),
    inputSchema={
        "type": "object",
        "properties": {},
    },
)


async def handle(client: LeakIXClient, arguments: dict[str, Any]) -> Any:
    """Handle list_plugins tool call."""
    r = await client.api.get_plugins()
    return r.json() if r.is_success() else []
