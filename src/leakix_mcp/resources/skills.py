"""SKILLS.md resource."""

from importlib.resources import files

from mcp.types import Resource

RESOURCE = Resource(
    uri="leakix://skills.md",
    name="skills",
    description="Usage guide and workflows for the LeakIX MCP server.",
    mime_type="text/markdown",
)


async def read() -> str:
    """Return the SKILLS.md content."""
    return files(__package__).joinpath("SKILLS.md").read_text(encoding="utf-8")
