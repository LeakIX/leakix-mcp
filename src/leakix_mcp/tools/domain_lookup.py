"""Look up a specific domain on LeakIX."""

from typing import Any

from leakix import AsyncClient
from pydantic import BaseModel, Field, field_validator

from ..address import is_hostname
from .helpers import build_tool, unwrap


class Args(BaseModel):
    """Arguments for domain_lookup."""

    domain: str = Field(description="Domain name (e.g., 'example.com').")

    @field_validator("domain")
    @classmethod
    def _must_be_hostname(cls, value: str) -> str:
        if not is_hostname(value):
            raise ValueError("must be a valid domain name")
        return value


TOOL = build_tool(
    "domain_lookup",
    "Get information about a specific domain. "
    "Returns services and data leaks associated with the domain and its "
    "subdomains, including exposed services, certificates, and potential "
    "security issues.",
    Args,
)


async def handle(client: AsyncClient, arguments: dict[str, Any]) -> Any:
    """Handle domain_lookup tool call."""
    args = Args.model_validate(arguments)
    return unwrap(await client.get_domain(args.domain))
