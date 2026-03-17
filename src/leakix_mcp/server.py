"""LeakIX MCP Server implementation."""

import json
import os
import sys
from typing import Any

from leakix import RawQuery, Scope
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .client import LeakIXClient

# Create server instance
server = Server("leakix-mcp")

# Global client instance
_client: LeakIXClient | None = None


def get_client() -> LeakIXClient:
    """Get or create the LeakIX client."""
    global _client
    if _client is None:
        api_key = os.environ.get("LEAKIX_API_KEY", "")
        if not api_key:
            raise ValueError(
                "LEAKIX_API_KEY environment variable is required. "
                "Get your API key from https://leakix.net/settings"
            )
        _client = LeakIXClient(api_key)
    return _client


def serialize_object(obj: Any) -> Any:
    """Serialize objects to dicts for JSON encoding."""
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    return str(obj)


def format_result(data: Any) -> str:
    """Format result data as JSON string.

    Handles L9Event and other objects by converting them to dicts.
    """
    if isinstance(data, list):
        data = [
            item.to_dict() if hasattr(item, "to_dict") else item
            for item in data
        ]
    elif isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list):
                data[key] = [
                    item.to_dict() if hasattr(item, "to_dict") else item
                    for item in value
                ]
    return json.dumps(data, indent=2, default=serialize_object)


@server.list_tools()  # type: ignore[no-untyped-call,untyped-decorator]
async def list_tools() -> list[Tool]:
    """List available LeakIX tools."""
    return [
        Tool(
            name="search_services",
            description=(
                "Search LeakIX for exposed services (open ports, software, "
                'protocols). Use query syntax like \'+country:"France" '
                "+port:22' or '+plugin:OpenSSH'. Returns detailed service "
                "info including IP, port, software, geolocation, network."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": (
                            "Search query. Examples: '+country:\"US\"', "
                            "'+port:3306', '+plugin:MySQL', "
                            "'+ip:192.168.0.0/16', '+host:example.com'"
                        ),
                    },
                    "page": {
                        "type": "integer",
                        "description": "Page number (0-indexed). Default: 0",
                        "default": 0,
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="search_leaks",
            description=(
                "Search LeakIX for data leaks and exposed databases. "
                "Returns information about leaked credentials, exposed "
                "databases, and data breaches. Use queries like "
                "'+leak.severity:critical' or '+leak.dataset.infected:true'."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": (
                            "Search query. Examples: "
                            "'+leak.severity:critical', "
                            "'+leak.dataset.rows:>1000', "
                            "'+plugin:GitConfigHttpPlugin'"
                        ),
                    },
                    "page": {
                        "type": "integer",
                        "description": "Page number (0-indexed). Default: 0",
                        "default": 0,
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="host_lookup",
            description=(
                "Get detailed information about a specific IP address. "
                "Returns all known services and data leaks associated with "
                "the IP, including open ports, software versions, SSL "
                "certificates, and any exposed data."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IPv4 or IPv6 address to lookup.",
                    },
                },
                "required": ["ip"],
            },
        ),
        Tool(
            name="domain_lookup",
            description=(
                "Get information about a specific domain. "
                "Returns services and data leaks associated with the domain "
                "and its subdomains, including exposed services, "
                "certificates, and potential security issues."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain name (e.g., 'example.com').",
                    },
                },
                "required": ["domain"],
            },
        ),
        Tool(
            name="list_subdomains",
            description=(
                "Enumerate discovered subdomains for a domain. "
                "Returns a list of subdomains found through various "
                "discovery methods."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain name to enumerate subdomains.",
                    },
                },
                "required": ["domain"],
            },
        ),
        Tool(
            name="list_plugins",
            description=(
                "Get the list of available LeakIX detection plugins. "
                "Plugins identify specific services, software, and "
                "vulnerabilities. Use plugin names in search queries "
                "with '+plugin:PluginName'."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="bulk_export",
            description=(
                "Bulk export leak data (requires Pro API). "
                "Returns aggregated results for large-scale analysis. "
                "Use this for exporting large datasets efficiently. "
                "Results include grouped events by target."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": (
                            "Search query. Examples: "
                            "'+plugin:GitConfigHttpPlugin', "
                            "'+country:FR +plugin:MongoOpenPlugin'"
                        ),
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
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
                        "description": (
                            "IP address or domain name to investigate."
                        ),
                    },
                },
                "required": ["target"],
            },
        ),
        Tool(
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
                        "description": ("IP address or domain to analyze."),
                    },
                },
                "required": ["target"],
            },
        ),
        Tool(
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
                        "description": (
                            "IP address or domain to find relations for."
                        ),
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
        ),
    ]


@server.call_tool()  # type: ignore[untyped-decorator]
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Execute a LeakIX tool."""
    client = get_client()

    try:
        if name == "search_services":
            query = arguments["query"]
            page = arguments.get("page", 0)
            r = await client.api.search(query, scope=Scope.SERVICE, page=page)
            return [
                TextContent(
                    type="text",
                    text=format_result(r.json() if r.is_success() else []),
                )
            ]

        elif name == "search_leaks":
            query = arguments["query"]
            page = arguments.get("page", 0)
            r = await client.api.search(query, scope=Scope.LEAK, page=page)
            return [
                TextContent(
                    type="text",
                    text=format_result(r.json() if r.is_success() else []),
                )
            ]

        elif name == "host_lookup":
            ip = arguments["ip"]
            r = await client.api.get_host(ip)
            return [
                TextContent(
                    type="text",
                    text=format_result(r.json() if r.is_success() else {}),
                )
            ]

        elif name == "domain_lookup":
            domain = arguments["domain"]
            r = await client.api.get_domain(domain)
            return [
                TextContent(
                    type="text",
                    text=format_result(r.json() if r.is_success() else {}),
                )
            ]

        elif name == "list_subdomains":
            domain = arguments["domain"]
            r = await client.api.get_subdomains(domain)
            return [
                TextContent(
                    type="text",
                    text=format_result(r.json() if r.is_success() else []),
                )
            ]

        elif name == "list_plugins":
            r = await client.api.get_plugins()
            return [
                TextContent(
                    type="text",
                    text=format_result(r.json() if r.is_success() else []),
                )
            ]

        elif name == "bulk_export":
            query = arguments["query"]
            r = await client.api.bulk_export(queries=[RawQuery(query)])
            return [
                TextContent(
                    type="text",
                    text=format_result(r.json() if r.is_success() else []),
                )
            ]

        elif name == "quick_recon":
            target = arguments["target"]
            result = await client.quick_recon(target)
            return [TextContent(type="text", text=format_result(result))]

        elif name == "exposure_report":
            target = arguments["target"]
            result = await client.exposure_report(target)
            return [TextContent(type="text", text=format_result(result))]

        elif name == "find_related":
            target = arguments["target"]
            relation_type = arguments.get("relation_type", "technology")
            result = await client.find_related(target, relation_type)
            return [TextContent(type="text", text=format_result(result))]

        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except ValueError as e:
        return [TextContent(type="text", text=f"Configuration error: {e}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {e}")]


async def run_server() -> None:
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main() -> None:
    """Entry point for the server."""
    import asyncio

    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Server error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
