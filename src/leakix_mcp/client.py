"""LeakIX MCP client wrapper using the official leakix library."""

from typing import Any

from leakix import AsyncClient, RawQuery


class LeakIXClient:
    """MCP client wrapper for LeakIX API using the official async client."""

    def __init__(self, api_key: str) -> None:
        """Initialize the LeakIX client.

        Args:
            api_key: LeakIX API key for authentication.
        """
        self._client = AsyncClient(api_key=api_key)

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.close()

    async def search(
        self,
        query: str,
        scope: str = "service",
        page: int = 0,
    ) -> list[Any]:
        """Search LeakIX for services or leaks.

        Args:
            query: Search query string.
            scope: Either "service" or "leak".
            page: Page number (0-indexed).

        Returns:
            List of L9Event results.
        """
        return await self._client.search(query, scope=scope, page=page)

    async def get_host(self, ip: str) -> dict[str, list[Any]]:
        """Get information about a specific IP address.

        Args:
            ip: IPv4 or IPv6 address.

        Returns:
            Dict with 'services' and 'leaks' lists.
        """
        return await self._client.get_host(ip)

    async def get_domain(self, domain: str) -> dict[str, list[Any]]:
        """Get information about a specific domain.

        Args:
            domain: Domain name.

        Returns:
            Dict with 'services' and 'leaks' lists.
        """
        return await self._client.get_domain(domain)

    async def get_subdomains(self, domain: str) -> list[Any]:
        """Get subdomains for a domain.

        Args:
            domain: Domain name.

        Returns:
            List of subdomain records.
        """
        return await self._client.get_subdomains(domain)

    async def get_plugins(self) -> list[Any]:
        """Get list of available plugins.

        Returns:
            List of plugin information.
        """
        return await self._client.get_plugins()

    async def bulk_export(
        self,
        query: str,
        max_results: int = 1000,
    ) -> list[Any]:
        """Bulk export leaks (Pro API feature).

        Args:
            query: Search query string.
            max_results: Maximum number of results to return.

        Returns:
            List of aggregation results.
        """
        queries = [RawQuery(query)]
        results: list[Any] = []
        async for item in self._client.bulk_export_stream(queries):
            results.append(item)
            if len(results) >= max_results:
                break
        return results

    async def quick_recon(self, target: str) -> dict[str, Any]:
        """Quick reconnaissance on a target (IP or domain).

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

        Returns:
            API status with Pro detection and available features.
        """
        status: dict[str, Any] = {
            "authenticated": True,
            "is_pro": False,
            "features": [
                "search",
                "host_lookup",
                "domain_lookup",
                "subdomains",
            ],
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

    async def exposure_report(self, target: str) -> dict[str, Any]:
        """Generate a security exposure report for a target.

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
        services = data.get("services") or []
        report["services"] = services
        report["summary"]["total_services"] = len(services)

        ports_seen: set[int] = set()
        technologies_seen: set[str] = set()
        countries_seen: set[str] = set()

        for svc in services:
            if hasattr(svc, "port"):
                ports_seen.add(svc.port)
            if hasattr(svc, "software") and svc.software:
                if hasattr(svc.software, "name") and svc.software.name:
                    technologies_seen.add(svc.software.name)
            if hasattr(svc, "geoip") and svc.geoip:
                if hasattr(svc.geoip, "country_name") and svc.geoip.country_name:
                    countries_seen.add(svc.geoip.country_name)

        report["summary"]["exposed_ports"] = sorted(ports_seen)
        report["summary"]["technologies"] = sorted(technologies_seen)
        report["summary"]["countries"] = sorted(countries_seen)

        # Process leaks
        leaks = data.get("leaks") or []
        report["leaks"] = leaks
        report["summary"]["total_leaks"] = len(leaks)

        # Identify critical findings
        critical: list[str] = []
        for leak in leaks:
            severity = None
            if hasattr(leak, "leak") and leak.leak:
                if hasattr(leak.leak, "severity"):
                    severity = leak.leak.severity
            if severity in ("critical", "high"):
                plugin = getattr(leak, "event_source", None)
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

        services = data.get("services") or []
        if not services:
            return results

        first_svc = services[0]

        if relation_type == "technology":
            software_name = None
            if hasattr(first_svc, "software") and first_svc.software:
                if hasattr(first_svc.software, "name"):
                    software_name = first_svc.software.name

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

            if network:
                query = f'+network:"{network}"'
                results["search_query"] = query
                related = await self.search(query, scope="service", page=0)
                results["related"] = related

        return results
