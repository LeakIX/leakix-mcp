"""Look up a specific IP address on LeakIX."""

from typing import Any

from leakix import AsyncClient
from pydantic import BaseModel, Field, field_validator

from ..address import is_ip, parse_host
from .helpers import build_tool, unwrap


class Args(BaseModel):
    """Arguments for host_lookup."""

    ip: str = Field(description="IPv4 or IPv6 address to lookup.")

    @field_validator("ip")
    @classmethod
    def _must_be_ip(cls, value: str) -> str:
        if not is_ip(parse_host(value)):
            raise ValueError("must be an IPv4 or IPv6 address")
        return value


TOOL = build_tool(
    "host_lookup",
    "Get detailed information about a specific IP address. "
    "Returns all known services and data leaks associated with the IP, "
    "including open ports, software versions, SSL certificates, and any "
    "exposed data.",
    Args,
)


async def handle(client: AsyncClient, arguments: dict[str, Any]) -> Any:
    """Handle host_lookup tool call."""
    args = Args.model_validate(arguments)
    return unwrap(await client.get_host(args.ip))
