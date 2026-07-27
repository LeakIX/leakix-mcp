"""List available LeakIX detection plugins."""

from typing import Any

from leakix import AsyncClient
from pydantic import BaseModel

from .helpers import build_tool, unwrap


class Args(BaseModel):
    """Arguments for list_plugins (none)."""


TOOL = build_tool(
    "list_plugins",
    "Get the list of available LeakIX detection plugins. "
    "Plugins identify specific services, software, and vulnerabilities. "
    "Use plugin names in search queries with '+plugin:PluginName'.",
    Args,
)


async def handle(client: AsyncClient, arguments: dict[str, Any]) -> Any:
    """Handle list_plugins tool call."""
    Args.model_validate(arguments)
    return unwrap(await client.get_plugins())
