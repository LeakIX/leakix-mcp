"""LeakIX MCP Server implementation."""

import json
import os
import sys
from typing import Any

from l9format import l9format
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


def serialize_l9event(obj: Any) -> Any:
    """Serialize L9Event objects to dicts for JSON encoding."""
    if isinstance(obj, l9format.L9Event):
        return obj.to_dict()
    return str(obj)


def format_result(data: Any) -> str:
    """Format result data as JSON string.

    Handles L9Event objects by converting them to dicts.
    """
    if isinstance(data, list):
        data = [
            item.to_dict() if isinstance(item, l9format.L9Event) else item
            for item in data
        ]
    elif isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list):
                data[key] = [
                    item.to_dict()
                    if isinstance(item, l9format.L9Event)
                    else item
                    for item in value
                ]
    return json.dumps(data, indent=2, default=serialize_l9event)


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
    ]


@server.call_tool()  # type: ignore[untyped-decorator]
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Execute a LeakIX tool."""
    client = get_client()

    try:
        if name == "search_services":
            query = arguments["query"]
            page = arguments.get("page", 0)
            results = await client.search(query, scope="service", page=page)
            return [TextContent(type="text", text=format_result(results))]

        elif name == "search_leaks":
            query = arguments["query"]
            page = arguments.get("page", 0)
            results = await client.search(query, scope="leak", page=page)
            return [TextContent(type="text", text=format_result(results))]

        elif name == "host_lookup":
            ip = arguments["ip"]
            result = await client.get_host(ip)
            return [TextContent(type="text", text=format_result(result))]

        elif name == "domain_lookup":
            domain = arguments["domain"]
            result = await client.get_domain(domain)
            return [TextContent(type="text", text=format_result(result))]

        elif name == "list_subdomains":
            domain = arguments["domain"]
            subdomains = await client.get_subdomains(domain)
            return [TextContent(type="text", text=format_result(subdomains))]

        elif name == "list_plugins":
            plugins = await client.get_plugins()
            return [TextContent(type="text", text=format_result(plugins))]

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
