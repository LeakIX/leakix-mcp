"""Find targets related to a given IP or domain."""

from typing import Any

from leakix import AsyncClient, Scope
from mcp.types import Tool

from .helpers import get_field, is_ip

TOOL = Tool(
    name="find_related",
    description=(
        "Find targets related to a given IP or domain. "
        "Discovers similar targets based on shared "
        "characteristics like technology stack, ASN, "
        "or network range. Useful for attack surface mapping."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": ("IP address or domain to find relations for."),
            },
            "relation_type": {
                "type": "string",
                "enum": ["technology", "asn", "network"],
                "description": (
                    "Type of relation to search for. "
                    "technology: same software stack, "
                    "asn: same autonomous system, "
                    "network: same network range. "
                    "Default: technology"
                ),
                "default": "technology",
            },
        },
        "required": ["target"],
    },
)


def _build_search_query(
    services: list[Any],
    relation_type: str,
) -> str | None:
    """Build a search query from services based on relation type."""
    if not services:
        return None

    first_svc = services[0]

    if relation_type == "technology":
        for svc in services:
            service = get_field(svc, "service")
            software = get_field(service, "software") if service else None
            name = get_field(software, "name") if software else None
            if name:
                return f'+service.software.name:"{name}"'

    elif relation_type == "asn":
        network = get_field(first_svc, "network")
        asn = get_field(network, "asn") if network else None
        if asn:
            return f"+asn:{asn}"

    elif relation_type == "network":
        network_obj = get_field(first_svc, "network")
        network = get_field(network_obj, "network") if network_obj else None
        if network:
            return f'+network.network:"{network}"'

    return None


async def handle(client: AsyncClient, arguments: dict[str, Any]) -> Any:
    """Handle find_related tool call."""
    target = arguments["target"]
    relation_type = arguments.get("relation_type", "technology")
    results: dict[str, Any] = {
        "target": target,
        "relation_type": relation_type,
        "related": [],
    }

    if is_ip(target):
        r = await client.get_host(target)
    else:
        r = await client.get_domain(target)

    data = r.json() if r.is_success() else {}
    services = data.get("services") or []
    query = _build_search_query(services, relation_type)

    if query:
        results["search_query"] = query
        r = await client.search(query, scope=Scope.SERVICE, page=0)
        results["related"] = r.json() if r.is_success() else []

    return results
