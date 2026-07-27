"""Runtime feature flags.

Features are opt-in behaviours toggled by environment variables, so
experimental or not-yet-production code ships inert and is enabled only
when explicitly requested.
"""

import os
from dataclasses import dataclass

_TRUE = {"1", "true", "yes", "on"}


def _env_flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in _TRUE


@dataclass(frozen=True)
class Feature:
    """A named, environment-toggled feature flag."""

    name: str
    env_var: str
    description: str
    default: bool = False

    def enabled(self) -> bool:
        """Return whether the feature is enabled in the environment."""
        return _env_flag(self.env_var, self.default)


HTTP_TRANSPORT = Feature(
    name="http-transport",
    env_var="LEAKIX_MCP_ENABLE_HTTP",
    description=(
        "Experimental Streamable HTTP transport. Not production-ready; "
        "off by default."
    ),
)
