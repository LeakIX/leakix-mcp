"""Search LeakIX for data leaks."""

from typing import Any

from leakix import AsyncClient, Scope
from pydantic import BaseModel, Field

from .helpers import build_tool, unwrap


class Args(BaseModel):
    """Arguments for search_leaks."""

    query: str = Field(
        description=(
            "Search query. Examples: '+leak.severity:critical', "
            "'+leak.dataset.rows:>1000', '+plugin:GitConfigHttpPlugin'"
        )
    )
    page: int = Field(0, ge=0, description="Page number (0-indexed).")


TOOL = build_tool(
    "search_leaks",
    "Search LeakIX for data leaks and exposed databases. "
    "Returns information about leaked credentials, exposed "
    "databases, and data breaches. Use queries like "
    "'+leak.severity:critical' or '+leak.dataset.infected:true'.",
    Args,
)


async def handle(client: AsyncClient, arguments: dict[str, Any]) -> Any:
    """Handle search_leaks tool call."""
    args = Args.model_validate(arguments)
    return unwrap(
        await client.search(args.query, scope=Scope.LEAK, page=args.page)
    )
