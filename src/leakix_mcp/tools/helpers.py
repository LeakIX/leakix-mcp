"""Shared helper functions for MCP tools."""

from typing import Any


def is_ip(target: str) -> bool:
    """Check if target is an IPv4 address."""
    try:
        parts = target.split(".")
        return len(parts) == 4 and all(
            p.isdigit() and 0 <= int(p) <= 255 for p in parts
        )
    except Exception:
        return False


def get_field(obj: Any, field: str) -> Any:
    """Get field from object or dict."""
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)
