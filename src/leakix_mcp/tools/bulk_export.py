"""Bulk export leak data from LeakIX."""

from typing import Any

from leakix import AsyncClient, RawQuery
from pydantic import BaseModel, Field

from .helpers import build_tool, unwrap


class Args(BaseModel):
    """Arguments for bulk_export."""

    query: str = Field(
        description=(
            "Search query. Examples: '+plugin:GitConfigHttpPlugin', "
            "'+country:FR +plugin:MongoOpenPlugin'"
        )
    )


TOOL = build_tool(
    "bulk_export",
    "Bulk export leak data (requires Pro API). "
    "Returns aggregated results for large-scale analysis. "
    "Use this for exporting large datasets efficiently. "
    "Results include grouped events by target.",
    Args,
)


async def handle(client: AsyncClient, arguments: dict[str, Any]) -> Any:
    """Handle bulk_export tool call."""
    args = Args.model_validate(arguments)
    return unwrap(await client.bulk_export(queries=[RawQuery(args.query)]))
