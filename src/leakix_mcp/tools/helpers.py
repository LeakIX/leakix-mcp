"""Shared helpers for MCP tools."""

import contextlib
from typing import Any

from leakix import AbstractResponse, AsyncClient
from mcp.types import Tool
from pydantic import BaseModel

from ..address import is_ip, parse_host
from ..errors import LeakixAPIError


def get_field(obj: Any, field: str) -> Any:
    """Get a field from an object or a dict, or None if absent."""
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


def unwrap(response: AbstractResponse) -> Any:
    """Return the response JSON, or raise LeakixAPIError on failure.

    This surfaces API failures (auth, rate limit, 5xx) instead of
    collapsing them into an empty result.
    """
    if response.is_success():
        return response.json()
    payload: Any = None
    with contextlib.suppress(Exception):
        payload = response.json()
    raise LeakixAPIError(response.status_code(), payload)


async def resolve_target(client: AsyncClient, target: str) -> tuple[str, Any]:
    """Look up an IP or domain, returning (kind, data).

    kind is 'ip' or 'domain'. The target is validated through the address
    module (so IPv4, IPv6 and hostnames route correctly); an invalid host
    raises InvalidHostError and a failed lookup raises LeakixAPIError.
    """
    host = parse_host(target)
    if is_ip(host):
        return "ip", unwrap(await client.get_host(str(host)))
    return "domain", unwrap(await client.get_domain(str(host)))


def build_tool(name: str, description: str, args: type[BaseModel]) -> Tool:
    """Build an MCP Tool whose input schema is derived from a model.

    The pydantic model is the single source of truth: it generates the
    JSON input schema and validates incoming arguments in the handler.
    """
    return Tool(
        name=name,
        description=description,
        input_schema=args.model_json_schema(),
    )
