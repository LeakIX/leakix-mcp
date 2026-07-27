"""LeakIX MCP Server - Security research and reconnaissance via LeakIX API."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("leakix-mcp")
except PackageNotFoundError:  # pragma: no cover - not installed
    __version__ = "0.0.0"
