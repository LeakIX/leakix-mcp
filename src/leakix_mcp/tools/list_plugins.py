"""List available LeakIX detection plugins."""

from typing import Any

from leakix import AsyncClient
from mcp.types import Tool

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


async def handle(client: AsyncClient, arguments: dict[str, Any]) -> Any:
    """Handle list_plugins tool call."""
    r = await client.get_plugins()
    return r.json() if r.is_success() else []
