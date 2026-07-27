"""Enumerate subdomains for a domain on LeakIX."""

from typing import Any

from leakix import AsyncClient
from pydantic import BaseModel, Field, field_validator

from ..address import is_hostname
from .helpers import build_tool, unwrap


class Args(BaseModel):
    """Arguments for list_subdomains."""

    domain: str = Field(description="Domain name to enumerate subdomains.")

    @field_validator("domain")
    @classmethod
    def _must_be_hostname(cls, value: str) -> str:
        if not is_hostname(value):
            raise ValueError("must be a valid domain name")
        return value


TOOL = build_tool(
    "list_subdomains",
    "Enumerate discovered subdomains for a domain. "
    "Returns a list of subdomains found through various discovery "
    "methods.",
    Args,
)


async def handle(client: AsyncClient, arguments: dict[str, Any]) -> Any:
    """Handle list_subdomains tool call."""
    args = Args.model_validate(arguments)
    return unwrap(await client.get_subdomains(args.domain))
