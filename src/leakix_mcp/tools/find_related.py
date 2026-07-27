"""Find targets related to a given IP or domain."""

from typing import Any, Literal

from leakix import AsyncClient, Scope
from pydantic import BaseModel, Field

from .helpers import build_tool, get_field, resolve_target, unwrap

RelationType = Literal["technology", "asn", "network"]


class Args(BaseModel):
    """Arguments for find_related."""

    target: str = Field(
        description="IP address or domain to find relations for."
    )
    relation_type: RelationType = Field(
        "technology",
        description=(
            "Type of relation to search for. "
            "technology: same software stack, asn: same autonomous system, "
            "network: same network range."
        ),
    )


TOOL = build_tool(
    "find_related",
    "Find targets related to a given IP or domain. "
    "Discovers similar targets based on shared characteristics like "
    "technology stack, ASN, or network range. Useful for attack surface "
    "mapping.",
    Args,
)


def _build_search_query(
    services: list[Any], relation_type: RelationType
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
    args = Args.model_validate(arguments)
    results: dict[str, Any] = {
        "target": args.target,
        "relation_type": args.relation_type,
        "related": [],
    }

    _, data = await resolve_target(client, args.target)
    services = data.get("services") or []
    query = _build_search_query(services, args.relation_type)

    if query:
        results["search_query"] = query
        results["related"] = unwrap(
            await client.search(query, scope=Scope.SERVICE, page=0)
        )
    return results
