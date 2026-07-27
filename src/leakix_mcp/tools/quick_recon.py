"""Quick reconnaissance on a target IP or domain."""

from typing import Any

from leakix import AsyncClient
from pydantic import BaseModel, Field

from .helpers import build_tool, resolve_target, unwrap


class Args(BaseModel):
    """Arguments for quick_recon."""

    target: str = Field(description="IP address or domain name to investigate.")


TOOL = build_tool(
    "quick_recon",
    "Quick reconnaissance on a target IP or domain. "
    "Automatically detects target type and performs: "
    "- For IPs: host lookup with services and leaks "
    "- For domains: domain lookup + subdomain enumeration "
    "Use this for fast initial assessment of a target.",
    Args,
)


async def handle(client: AsyncClient, arguments: dict[str, Any]) -> Any:
    """Handle quick_recon tool call."""
    args = Args.model_validate(arguments)
    kind, data = await resolve_target(client, args.target)
    results: dict[str, Any] = {"target": args.target, "type": kind}
    if kind == "ip":
        results["host"] = data
    else:
        results["domain"] = data
        results["subdomains"] = unwrap(await client.get_subdomains(args.target))
    return results
