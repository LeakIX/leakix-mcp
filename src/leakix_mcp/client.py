"""LeakIX API client."""

import asyncio
import json
import logging
from typing import Any

import httpx
from l9format import l9format

logger = logging.getLogger(__name__)


def parse_l9event(data: dict[str, Any]) -> l9format.L9Event | dict[str, Any]:
    """Parse a dictionary into an L9Event, falling back to dict on error.

    Args:
        data: Raw event data from the API.

    Returns:
        Parsed L9Event or original dict if parsing fails.
    """
    try:
        return l9format.L9Event.from_dict(data)
    except Exception as e:
        logger.debug("Failed to parse L9Event: %s", e)
        return data


def parse_l9events(
    data: list[dict[str, Any]],
) -> list[l9format.L9Event | dict[str, Any]]:
    """Parse a list of dictionaries into L9Events.

    Args:
        data: List of raw event data from the API.

    Returns:
        List of parsed L9Events or original dicts.
    """
    return [parse_l9event(item) for item in data]


class LeakIXClient:
    """Async client for the LeakIX API."""

    BASE_URL = "https://leakix.net"
    DEFAULT_TIMEOUT = 30.0

    def __init__(self, api_key: str) -> None:
        """Initialize the LeakIX client.

        Args:
            api_key: LeakIX API key for authentication.
        """
        self.api_key = api_key
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.BASE_URL,
                headers={
                    "accept": "application/json",
                    "api-key": self.api_key,
                },
                timeout=self.DEFAULT_TIMEOUT,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def _handle_rate_limit(self, response: httpx.Response) -> None:
        """Handle rate limiting by waiting if necessary."""
        if response.status_code == 429:
            wait_ms = response.headers.get("x-limited-for", "1000")
            wait_seconds = int(wait_ms) / 1000
            await asyncio.sleep(wait_seconds)

    async def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[dict[str, Any]]:
        """Make an API request with rate limit handling.

        Args:
            method: HTTP method.
            path: API path.
            params: Query parameters.

        Returns:
            JSON response data.

        Raises:
            httpx.HTTPStatusError: If the request fails.
        """
        client = await self._get_client()
        response = await client.request(method, path, params=params)

        if response.status_code == 429:
            await self._handle_rate_limit(response)
            response = await client.request(method, path, params=params)

        response.raise_for_status()
        data: dict[str, Any] | list[dict[str, Any]] = response.json()
        return data

    async def search(
        self,
        query: str,
        scope: str = "service",
        page: int = 0,
    ) -> list[l9format.L9Event | dict[str, Any]]:
        """Search LeakIX for services or leaks.

        Args:
            query: Search query string.
            scope: Either "service" or "leak".
            page: Page number (0-indexed).

        Returns:
            List of L9Event results.
        """
        params = {"q": query, "scope": scope, "page": page}
        result = await self._request("GET", "/search", params=params)
        if isinstance(result, list):
            return parse_l9events(result)
        return []

    async def get_host(
        self,
        ip: str,
    ) -> dict[str, list[l9format.L9Event | dict[str, Any]]]:
        """Get information about a specific IP address.

        Args:
            ip: IPv4 or IPv6 address.

        Returns:
            Host information with Services and Leaks arrays.
        """
        result = await self._request("GET", f"/host/{ip}")
        if isinstance(result, dict):
            return {
                "Services": parse_l9events(result.get("Services") or []),
                "Leaks": parse_l9events(result.get("Leaks") or []),
            }
        return {"Services": [], "Leaks": []}

    async def get_domain(
        self,
        domain: str,
    ) -> dict[str, list[l9format.L9Event | dict[str, Any]]]:
        """Get information about a specific domain.

        Args:
            domain: Domain name.

        Returns:
            Domain information with Services and Leaks arrays.
        """
        result = await self._request("GET", f"/domain/{domain}")
        if isinstance(result, dict):
            return {
                "Services": parse_l9events(result.get("Services") or []),
                "Leaks": parse_l9events(result.get("Leaks") or []),
            }
        return {"Services": [], "Leaks": []}

    async def get_subdomains(
        self,
        domain: str,
    ) -> list[dict[str, Any]]:
        """Get subdomains for a domain.

        Args:
            domain: Domain name.

        Returns:
            List of subdomain records.
        """
        result = await self._request("GET", f"/api/subdomains/{domain}")
        if isinstance(result, list):
            return result
        return []

    async def get_plugins(self) -> list[dict[str, Any]]:
        """Get list of available plugins.

        Returns:
            List of plugin information.
        """
        result = await self._request("GET", "/api/plugins")
        if isinstance(result, list):
            return result
        return []

    async def bulk_export(
        self,
        query: str,
        max_results: int = 1000,
    ) -> list[dict[str, Any]]:
        """Bulk export leaks (Pro API feature).

        Streams results from the bulk endpoint and returns aggregations.

        Args:
            query: Search query string.
            max_results: Maximum number of results to return.

        Returns:
            List of aggregation results with events.
        """
        client = await self._get_client()
        params = {"q": query}

        results: list[dict[str, Any]] = []
        async with client.stream(
            "GET", "/bulk/search", params=params
        ) as response:
            if response.status_code == 429:
                await self._handle_rate_limit(response)
                async with client.stream(
                    "GET", "/bulk/search", params=params
                ) as retry_response:
                    retry_response.raise_for_status()
                    async for line in retry_response.aiter_lines():
                        if line and len(results) < max_results:
                            data = json.loads(line)
                            results.append(data)
                return results

            response.raise_for_status()
            async for line in response.aiter_lines():
                if line and len(results) < max_results:
                    data = json.loads(line)
                    results.append(data)

        return results

    async def quick_recon(
        self,
        target: str,
    ) -> dict[str, Any]:
        """Quick reconnaissance on a target (IP or domain).

        Performs host lookup, domain lookup, and subdomain enumeration.

        Args:
            target: IP address or domain name.

        Returns:
            Combined reconnaissance results.
        """
        results: dict[str, Any] = {"target": target, "type": "unknown"}

        # Detect if target is IP or domain
        is_ip = False
        try:
            parts = target.split(".")
            if len(parts) == 4 and all(
                p.isdigit() and 0 <= int(p) <= 255 for p in parts
            ):
                is_ip = True
        except Exception:
            pass

        if is_ip:
            results["type"] = "ip"
            results["host"] = await self.get_host(target)
        else:
            results["type"] = "domain"
            results["domain"] = await self.get_domain(target)
            results["subdomains"] = await self.get_subdomains(target)

        return results

    async def check_api_status(self) -> dict[str, Any]:
        """Check API status and detect Pro subscription.

        Tests a Pro-only plugin to detect subscription level.

        Returns:
            API status with Pro detection and available features.
        """
        status: dict[str, Any] = {
            "authenticated": True,
            "is_pro": False,
            "features": ["search", "host_lookup", "domain_lookup", "subdomains"],
        }

        # Test Pro by querying a Pro-only plugin (WpPlugin has data)
        try:
            result = await self.search("+plugin:WpPlugin", scope="leak", page=0)
            if result and len(result) > 0:
                status["is_pro"] = True
                status["features"].extend(["bulk_export", "pro_plugins"])
        except Exception:
            pass

        # Get available plugins count
        try:
            plugins = await self.get_plugins()
            status["plugins_count"] = len(plugins)
        except Exception:
            status["plugins_count"] = 0

        return status

    async def exposure_report(
        self,
        target: str,
    ) -> dict[str, Any]:
        """Generate a security exposure report for a target.

        Combines all available data into a structured security report.

        Args:
            target: IP address or domain name.

        Returns:
            Structured security exposure report.
        """
        report: dict[str, Any] = {
            "target": target,
            "summary": {
                "total_services": 0,
                "total_leaks": 0,
                "critical_findings": [],
                "exposed_ports": [],
                "technologies": [],
                "countries": [],
            },
            "services": [],
            "leaks": [],
            "subdomains": [],
            "risk_level": "unknown",
        }

        # Detect target type and gather data
        is_ip = False
        try:
            parts = target.split(".")
            if len(parts) == 4 and all(
                p.isdigit() and 0 <= int(p) <= 255 for p in parts
            ):
                is_ip = True
        except Exception:
            pass

        if is_ip:
            data = await self.get_host(target)
        else:
            data = await self.get_domain(target)
            try:
                report["subdomains"] = await self.get_subdomains(target)
            except Exception:
                pass

        # Process services
        services = data.get("Services") or []
        report["services"] = services
        report["summary"]["total_services"] = len(services)

        ports_seen: set[int] = set()
        technologies_seen: set[str] = set()
        countries_seen: set[str] = set()

        for svc in services:
            if hasattr(svc, "port"):
                ports_seen.add(svc.port)
            elif isinstance(svc, dict):
                ports_seen.add(svc.get("port", 0))

            if hasattr(svc, "software") and svc.software:
                if hasattr(svc.software, "name") and svc.software.name:
                    technologies_seen.add(svc.software.name)
            elif isinstance(svc, dict) and svc.get("software"):
                tech = svc["software"].get("name")
                if tech:
                    technologies_seen.add(tech)

            if hasattr(svc, "geoip") and svc.geoip:
                if hasattr(svc.geoip, "country_name") and svc.geoip.country_name:
                    countries_seen.add(svc.geoip.country_name)
            elif isinstance(svc, dict) and svc.get("geoip"):
                country = svc["geoip"].get("country_name")
                if country:
                    countries_seen.add(country)

        report["summary"]["exposed_ports"] = sorted(ports_seen)
        report["summary"]["technologies"] = sorted(technologies_seen)
        report["summary"]["countries"] = sorted(countries_seen)

        # Process leaks
        leaks = data.get("Leaks") or []
        report["leaks"] = leaks
        report["summary"]["total_leaks"] = len(leaks)

        # Identify critical findings
        critical: list[str] = []
        for leak in leaks:
            severity = None
            if hasattr(leak, "leak") and leak.leak:
                if hasattr(leak.leak, "severity"):
                    severity = leak.leak.severity
            elif isinstance(leak, dict) and leak.get("leak"):
                severity = leak["leak"].get("severity")

            if severity in ("critical", "high"):
                plugin = None
                if hasattr(leak, "event_source"):
                    plugin = leak.event_source
                elif isinstance(leak, dict):
                    plugin = leak.get("event_source")
                if plugin:
                    critical.append(f"{severity}: {plugin}")

        report["summary"]["critical_findings"] = critical

        # Calculate risk level
        if len(leaks) > 10 or len(critical) > 0:
            report["risk_level"] = "critical"
        elif len(leaks) > 5:
            report["risk_level"] = "high"
        elif len(leaks) > 0:
            report["risk_level"] = "medium"
        elif len(services) > 10:
            report["risk_level"] = "low"
        else:
            report["risk_level"] = "minimal"

        return report

    async def find_related(
        self,
        target: str,
        relation_type: str = "technology",
    ) -> dict[str, Any]:
        """Find targets related to the given target.

        Args:
            target: IP address or domain to find relations for.
            relation_type: Type of relation (technology, asn, network).

        Returns:
            Related targets based on shared characteristics.
        """
        results: dict[str, Any] = {
            "target": target,
            "relation_type": relation_type,
            "related": [],
        }

        # First get info about the target
        is_ip = False
        try:
            parts = target.split(".")
            if len(parts) == 4 and all(
                p.isdigit() and 0 <= int(p) <= 255 for p in parts
            ):
                is_ip = True
        except Exception:
            pass

        if is_ip:
            data = await self.get_host(target)
        else:
            data = await self.get_domain(target)

        services = data.get("Services") or []
        if not services:
            return results

        # Extract characteristics for searching
        first_svc = services[0]

        if relation_type == "technology":
            software_name = None
            if hasattr(first_svc, "software") and first_svc.software:
                if hasattr(first_svc.software, "name"):
                    software_name = first_svc.software.name
            elif isinstance(first_svc, dict) and first_svc.get("software"):
                software_name = first_svc["software"].get("name")

            if software_name:
                query = f'+software.name:"{software_name}"'
                results["search_query"] = query
                related = await self.search(query, scope="service", page=0)
                results["related"] = related

        elif relation_type == "asn":
            asn = None
            if hasattr(first_svc, "network") and first_svc.network:
                if hasattr(first_svc.network, "asn"):
                    asn = first_svc.network.asn
            elif isinstance(first_svc, dict) and first_svc.get("network"):
                asn = first_svc["network"].get("asn")

            if asn:
                query = f"+asn:{asn}"
                results["search_query"] = query
                related = await self.search(query, scope="service", page=0)
                results["related"] = related

        elif relation_type == "network":
            network = None
            if hasattr(first_svc, "network") and first_svc.network:
                if hasattr(first_svc.network, "network"):
                    network = first_svc.network.network
            elif isinstance(first_svc, dict) and first_svc.get("network"):
                network = first_svc["network"].get("network")

            if network:
                query = f'+network:"{network}"'
                results["search_query"] = query
                related = await self.search(query, scope="service", page=0)
                results["related"] = related

        return results
