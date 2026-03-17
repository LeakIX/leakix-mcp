"""Quick reconnaissance on a target IP or domain."""

from typing import Any

from leakix import AsyncClient
from mcp.types import Tool

from .helpers import is_ip

TOOL = Tool(
    name="quick_recon",
    description=(
        "Quick reconnaissance on a target IP or domain. "
        "Automatically detects target type and performs: "
        "- For IPs: host lookup with services and leaks "
        "- For domains: domain lookup + subdomain enumeration "
        "Use this for fast initial assessment of a target."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": ("IP address or domain name to investigate."),
            },
        },
        "required": ["target"],
    },
)


async def handle(client: AsyncClient, arguments: dict[str, Any]) -> Any:
    """Handle quick_recon tool call."""
    target = arguments["target"]
    results: dict[str, Any] = {"target": target, "type": "unknown"}

    if is_ip(target):
        results["type"] = "ip"
        r = await client.get_host(target)
        results["host"] = r.json() if r.is_success() else []
    else:
        results["type"] = "domain"
        r = await client.get_domain(target)
        results["domain"] = r.json() if r.is_success() else []
        r = await client.get_subdomains(target)
        results["subdomains"] = r.json() if r.is_success() else []

    return results
