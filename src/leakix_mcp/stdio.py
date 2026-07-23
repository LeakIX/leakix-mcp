"""Stdio transport."""

import os

from mcp.server.stdio import stdio_server

from .common import _api_key, server


async def run_stdio() -> None:
    """Run the MCP server over stdio."""
    api_key = os.environ.get("LEAKIX_API_KEY", "")
    if not api_key:
        raise ValueError(
            "LEAKIX_API_KEY environment variable is required. "
            "Get your API key from https://leakix.net/settings"
        )
    _api_key.set(api_key)

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )
