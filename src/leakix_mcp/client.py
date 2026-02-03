"""LeakIX MCP client with high-level reconnaissance methods."""

from typing import Any

from leakix import AsyncClient


class LeakIXClient:
    """MCP client for LeakIX with high-level recon methods.

    The `api` attribute exposes the underlying AsyncClient for direct access
    to core methods (search, get_host, get_domain, etc.).
    """

    def __init__(self, api_key: str) -> None:
        """Initialize the LeakIX client.

        Args:
            api_key: LeakIX API key for authentication.
        """
        self.api = AsyncClient(api_key=api_key)

    async def close(self) -> None:
        """Close the HTTP client."""
        await self.api.close()

    def _get_field(self, obj: Any, field: str) -> Any:
        """Get field from object or dict."""
        if obj is None:
            return None
        if isinstance(obj, dict):
            return obj.get(field)
        return getattr(obj, field, None)

    def _is_ip(self, target: str) -> bool:
        """Check if target is an IPv4 address."""
        try:
            parts = target.split(".")
            return len(parts) == 4 and all(
                p.isdigit() and 0 <= int(p) <= 255 for p in parts
            )
        except Exception:
            return False

    async def quick_recon(self, target: str) -> dict[str, Any]:
        """Quick reconnaissance on a target (IP or domain).

        Args:
            target: IP address or domain name.

        Returns:
            Combined reconnaissance results.
        """
        results: dict[str, Any] = {"target": target, "type": "unknown"}

        if self._is_ip(target):
            results["type"] = "ip"
            results["host"] = await self.api.get_host(target)
        else:
            results["type"] = "domain"
            results["domain"] = await self.api.get_domain(target)
            results["subdomains"] = await self.api.get_subdomains(target)

        return results

    async def check_api_status(self) -> dict[str, Any]:
        """Check API status and detect Pro subscription.

        Delegates to the underlying AsyncClient which caches the result.

        Returns:
            API status with Pro detection and available features.
        """
        return await self.api.get_api_status()

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

        if self._is_ip(target):
            data = await self.api.get_host(target)
        else:
            data = await self.api.get_domain(target)
            try:
                report["subdomains"] = await self.api.get_subdomains(target)
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
            port = self._get_field(svc, "port")
            if port:
                ports_seen.add(int(port) if isinstance(port, str) else port)
            service = self._get_field(svc, "service")
            if service:
                software = self._get_field(service, "software")
                if software:
                    name = self._get_field(software, "name")
                    if name:
                        technologies_seen.add(name)
            geoip = self._get_field(svc, "geoip")
            if geoip:
                country = self._get_field(geoip, "country_name")
                if country:
                    countries_seen.add(country)

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
            leak_data = self._get_field(leak, "leak")
            severity = self._get_field(leak_data, "severity") if leak_data else None
            if severity in ("critical", "high"):
                plugin = self._get_field(leak, "event_source")
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

        if self._is_ip(target):
            data = await self.api.get_host(target)
        else:
            data = await self.api.get_domain(target)

        services = data.get("services") or []
        if not services:
            return results

        first_svc = services[0]

        if relation_type == "technology":
            software_name = None
            for svc in services:
                service = self._get_field(svc, "service")
                software = self._get_field(service, "software") if service else None
                software_name = self._get_field(software, "name") if software else None
                if software_name:
                    break

            if software_name:
                query = f'+service.software.name:"{software_name}"'
                results["search_query"] = query
                results["related"] = await self.api.search(query, scope="service", page=0)

        elif relation_type == "asn":
            network = self._get_field(first_svc, "network")
            asn = self._get_field(network, "asn") if network else None

            if asn:
                query = f"+asn:{asn}"
                results["search_query"] = query
                results["related"] = await self.api.search(query, scope="service", page=0)

        elif relation_type == "network":
            network_obj = self._get_field(first_svc, "network")
            network = self._get_field(network_obj, "network") if network_obj else None

            if network:
                query = f'+network.network:"{network}"'
                results["search_query"] = query
                results["related"] = await self.api.search(query, scope="service", page=0)

        return results
