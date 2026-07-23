"""LeakIX MCP Server entry point."""

import argparse
import asyncio
import sys

from .http import parse_address, run_http
from .stdio import run_stdio


def main() -> None:
    """Entry point for the server."""
    parser = argparse.ArgumentParser(description="LeakIX MCP Server")
    parser.add_argument(
        "--server-address",
        default=None,
        help="Listen address for HTTP transport "
        "(e.g. '0.0.0.0:8080' or ':8081'). "
        "Defaults to stdio transport if not set.",
    )
    args = parser.parse_args()

    try:
        if args.server_address:
            host, port = parse_address(args.server_address)
            run_http(host, port)
        else:
            asyncio.run(run_stdio())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Server error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
