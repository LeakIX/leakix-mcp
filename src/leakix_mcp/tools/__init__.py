"""LeakIX MCP tools registry."""

from typing import Any

from leakix import AsyncClient
from mcp.types import Tool

from . import (
    bulk_export,
    domain_lookup,
    exposure_report,
    find_related,
    host_lookup,
    list_plugins,
    list_subdomains,
    quick_recon,
    search_leaks,
    search_services,
)

_MODULES = [
    bulk_export,
    domain_lookup,
    exposure_report,
    find_related,
    host_lookup,
    list_plugins,
    list_subdomains,
    quick_recon,
    search_leaks,
    search_services,
]

_HANDLERS: dict[str, Any] = {mod.TOOL.name: mod.handle for mod in _MODULES}


def get_tools() -> list[Tool]:
    """Return all registered MCP tools."""
    return [mod.TOOL for mod in _MODULES]


async def dispatch(
    client: AsyncClient, name: str, arguments: dict[str, Any]
) -> Any:
    """Dispatch a tool call to the appropriate handler.

    Returns None if the tool is not found, otherwise the handler result.
    """
    handler = _HANDLERS.get(name)
    if handler is None:
        return None
    return await handler(client, arguments)
