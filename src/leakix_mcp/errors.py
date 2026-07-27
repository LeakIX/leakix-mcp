"""Error types for the LeakIX MCP server."""

from typing import Any


class LeakixMCPError(Exception):
    """Base class for LeakIX MCP errors."""


class LeakixAPIError(LeakixMCPError):
    """A LeakIX API request did not succeed.

    Carries the HTTP status code and the parsed error payload (if any) so
    the failure is surfaced to the caller instead of being swallowed into
    an empty result.
    """

    def __init__(self, status_code: int, payload: Any = None) -> None:
        self.status_code = status_code
        self.payload = payload
        message = f"LeakIX API request failed (HTTP {status_code})"
        detail = _payload_message(payload)
        if detail:
            message = f"{message}: {detail}"
        super().__init__(message)


def _payload_message(payload: Any) -> str | None:
    """Extract a human-readable message from an error payload."""
    if isinstance(payload, dict):
        for key in ("error", "message", "detail"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                return value
    if isinstance(payload, str) and payload:
        return payload
    return None
