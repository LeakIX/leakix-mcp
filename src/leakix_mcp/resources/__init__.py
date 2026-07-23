"""LeakIX MCP resources registry."""

from collections.abc import Awaitable, Callable

from mcp.types import Resource

from . import skills

_MODULES = [skills]

_READERS: dict[str, Callable[[], Awaitable[str]]] = {
    str(mod.RESOURCE.uri): mod.read for mod in _MODULES
}


def get_resources() -> list[Resource]:
    """Return all registered MCP resources."""
    return [mod.RESOURCE for mod in _MODULES]


async def read_resource(uri: str) -> str | None:
    """Read a resource by URI. Returns None if not found."""
    reader = _READERS.get(uri)
    if reader is None:
        return None
    return await reader()
