"""Generate a security exposure report for a target."""

import contextlib
from typing import Any

from leakix import AsyncClient
from mcp.types import Tool

from .helpers import get_field, is_ip

TOOL = Tool(
    name="exposure_report",
    description=(
        "Generate a comprehensive security exposure report. "
        "Analyzes a target and returns: risk level, "
        "critical findings, exposed ports, technologies, "
        "leak summary, and recommendations. "
        "Perfect for security assessments."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "IP address or domain to analyze.",
            },
        },
        "required": ["target"],
    },
)


def _build_report(
    target: str,
    data: dict[str, Any],
    subdomains: list[Any],
) -> dict[str, Any]:
    """Build a structured exposure report from API data."""
    services = data.get("services") or []
    leaks = data.get("leaks") or []

    ports_seen: set[int] = set()
    technologies_seen: set[str] = set()
    countries_seen: set[str] = set()

    for svc in services:
        port = get_field(svc, "port")
        if port:
            ports_seen.add(int(port) if isinstance(port, str) else port)
        service = get_field(svc, "service")
        if service:
            software = get_field(service, "software")
            if software:
                name = get_field(software, "name")
                if name:
                    technologies_seen.add(name)
        geoip = get_field(svc, "geoip")
        if geoip:
            country = get_field(geoip, "country_name")
            if country:
                countries_seen.add(country)

    critical: list[str] = []
    for leak in leaks:
        leak_data = get_field(leak, "leak")
        severity = get_field(leak_data, "severity") if leak_data else None
        if severity in ("critical", "high"):
            plugin = get_field(leak, "event_source")
            if plugin:
                critical.append(f"{severity}: {plugin}")

    if len(leaks) > 10 or len(critical) > 0:
        risk_level = "critical"
    elif len(leaks) > 5:
        risk_level = "high"
    elif len(leaks) > 0:
        risk_level = "medium"
    elif len(services) > 10:
        risk_level = "low"
    else:
        risk_level = "minimal"

    return {
        "target": target,
        "summary": {
            "total_services": len(services),
            "total_leaks": len(leaks),
            "critical_findings": critical,
            "exposed_ports": sorted(ports_seen),
            "technologies": sorted(technologies_seen),
            "countries": sorted(countries_seen),
        },
        "services": services,
        "leaks": leaks,
        "subdomains": subdomains,
        "risk_level": risk_level,
    }


async def handle(client: AsyncClient, arguments: dict[str, Any]) -> Any:
    """Handle exposure_report tool call."""
    target = arguments["target"]
    subdomains: list[Any] = []

    if is_ip(target):
        r = await client.get_host(target)
    else:
        r = await client.get_domain(target)
        with contextlib.suppress(Exception):
            sub_r = await client.get_subdomains(target)
            subdomains = sub_r.json() if sub_r.is_success() else []

    data = r.json() if r.is_success() else {}
    return _build_report(target, data, subdomains)
