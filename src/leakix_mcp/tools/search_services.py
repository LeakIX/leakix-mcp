"""Search LeakIX for exposed services."""

from typing import Any

from leakix import AsyncClient, Scope
from pydantic import BaseModel, Field

from .helpers import build_tool, unwrap


class Args(BaseModel):
    """Arguments for search_services."""

    query: str = Field(
        description=(
            "Search query. Examples: '+country:\"US\"', '+port:3306', "
            "'+plugin:MySQL', '+ip:192.168.0.0/16', '+host:example.com'"
        )
    )
    page: int = Field(0, ge=0, description="Page number (0-indexed).")


TOOL = build_tool(
    "search_services",
    "Search LeakIX for exposed services (open ports, software, "
    "protocols). Use query syntax like '+country:\"France\" +port:22' "
    "or '+plugin:OpenSSH'. Returns detailed service info including IP, "
    "port, software, geolocation, network.",
    Args,
)


async def handle(client: AsyncClient, arguments: dict[str, Any]) -> Any:
    """Handle search_services tool call."""
    args = Args.model_validate(arguments)
    return unwrap(
        await client.search(args.query, scope=Scope.SERVICE, page=args.page)
    )
