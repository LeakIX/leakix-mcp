"""Tests for the LeakIX MCP client."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from leakix_mcp.client import LeakIXClient

# Sample API response data
SAMPLE_SERVICE_EVENT = {
    "event_type": "service",
    "event_source": "HttpPlugin",
    "ip": "192.168.1.1",
    "port": "80",
    "host": "example.com",
    "protocol": "http",
    "summary": "HTTP Server",
    "time": "2026-01-15T10:30:00Z",
    "service": {
        "software": {
            "name": "nginx",
            "version": "1.18.0",
            "os": "Linux",
        },
    },
    "geoip": {
        "country_name": "United States",
        "country_iso_code": "US",
    },
    "network": {
        "organization_name": "Example ISP",
        "asn": 12345,
        "network": "192.168.0.0/16",
    },
}

SAMPLE_LEAK_EVENT = {
    "event_type": "leak",
    "event_source": "GitConfigHttpPlugin",
    "ip": "10.0.0.1",
    "port": "443",
    "host": "leaked.example.com",
    "protocol": "https",
    "summary": "Exposed Git configuration",
    "time": "2026-01-15T11:00:00Z",
    "leak": {
        "stage": "open",
        "type": "config_leak",
        "severity": "high",
    },
}

SAMPLE_SUBDOMAIN = {
    "subdomain": "api.example.com",
    "distinct_ips": ["192.168.1.1", "192.168.1.2"],
    "last_seen": "2026-01-15T12:00:00Z",
}

SAMPLE_PLUGIN = {
    "name": "HttpPlugin",
    "description": "HTTP service detection",
}


def _mock_response(data: object) -> MagicMock:
    """Create a mock AbstractResponse that behaves like SuccessResponse."""
    resp = MagicMock()
    resp.is_success.return_value = True
    resp.is_error.return_value = False
    resp.json.return_value = data
    resp.status_code.return_value = 200
    return resp


class TestLeakIXClientHelpers:
    """Tests for LeakIXClient helper methods."""

    def test_is_ip_valid(self) -> None:
        client = LeakIXClient(api_key="test")
        assert client._is_ip("192.168.1.1") is True
        assert client._is_ip("0.0.0.0") is True
        assert client._is_ip("255.255.255.255") is True

    def test_is_ip_invalid(self) -> None:
        client = LeakIXClient(api_key="test")
        assert client._is_ip("example.com") is False
        assert client._is_ip("256.1.1.1") is False
        assert client._is_ip("1.2.3") is False
        assert client._is_ip("") is False

    def test_get_field_dict(self) -> None:
        client = LeakIXClient(api_key="test")
        assert client._get_field({"name": "nginx"}, "name") == "nginx"
        assert client._get_field({"name": "nginx"}, "version") is None

    def test_get_field_none(self) -> None:
        client = LeakIXClient(api_key="test")
        assert client._get_field(None, "name") is None


class TestLeakIXClient:
    """Tests for the LeakIX API client methods."""

    @pytest.fixture
    def client(self) -> LeakIXClient:
        return LeakIXClient(api_key="test-api-key")

    @pytest.mark.asyncio
    async def test_quick_recon_ip(self, client: LeakIXClient) -> None:
        """Test quick recon on an IP address."""
        mock_host_data = {
            "services": [SAMPLE_SERVICE_EVENT],
            "leaks": [],
        }

        with patch.object(
            client.api, "get_host", new_callable=AsyncMock
        ) as mock:
            mock.return_value = _mock_response(mock_host_data)
            result = await client.quick_recon("192.168.1.1")

        assert result["type"] == "ip"
        assert result["host"] == mock_host_data

    @pytest.mark.asyncio
    async def test_quick_recon_domain(self, client: LeakIXClient) -> None:
        """Test quick recon on a domain."""
        mock_domain_data = {
            "services": [SAMPLE_SERVICE_EVENT],
            "leaks": [SAMPLE_LEAK_EVENT],
        }

        with (
            patch.object(
                client.api,
                "get_domain",
                new_callable=AsyncMock,
            ) as mock_domain,
            patch.object(
                client.api,
                "get_subdomains",
                new_callable=AsyncMock,
            ) as mock_subs,
        ):
            mock_domain.return_value = _mock_response(mock_domain_data)
            mock_subs.return_value = _mock_response([SAMPLE_SUBDOMAIN])
            result = await client.quick_recon("example.com")

        assert result["type"] == "domain"
        assert result["domain"] == mock_domain_data
        assert len(result["subdomains"]) == 1

    @pytest.mark.asyncio
    async def test_exposure_report_ip(self, client: LeakIXClient) -> None:
        """Test exposure report for an IP."""
        mock_data = {
            "services": [SAMPLE_SERVICE_EVENT],
            "leaks": [SAMPLE_LEAK_EVENT],
        }

        with patch.object(
            client.api, "get_host", new_callable=AsyncMock
        ) as mock:
            mock.return_value = _mock_response(mock_data)
            report = await client.exposure_report("192.168.1.1")

        assert report["target"] == "192.168.1.1"
        assert report["summary"]["total_services"] == 1
        assert report["summary"]["total_leaks"] == 1
        assert 80 in report["summary"]["exposed_ports"]
        assert "nginx" in report["summary"]["technologies"]
        assert "United States" in report["summary"]["countries"]
        assert len(report["summary"]["critical_findings"]) == 1
        assert report["risk_level"] == "critical"

    @pytest.mark.asyncio
    async def test_exposure_report_no_leaks(self, client: LeakIXClient) -> None:
        """Test exposure report with no leaks gives low risk."""
        mock_data = {
            "services": [SAMPLE_SERVICE_EVENT],
            "leaks": [],
        }

        with patch.object(
            client.api, "get_host", new_callable=AsyncMock
        ) as mock:
            mock.return_value = _mock_response(mock_data)
            report = await client.exposure_report("192.168.1.1")

        assert report["risk_level"] == "minimal"
        assert report["summary"]["total_leaks"] == 0

    @pytest.mark.asyncio
    async def test_exposure_report_empty(self, client: LeakIXClient) -> None:
        """Test exposure report with no data."""
        mock_data = {"services": [], "leaks": []}

        with patch.object(
            client.api, "get_host", new_callable=AsyncMock
        ) as mock:
            mock.return_value = _mock_response(mock_data)
            report = await client.exposure_report("10.0.0.1")

        assert report["risk_level"] == "minimal"
        assert report["summary"]["total_services"] == 0

    @pytest.mark.asyncio
    async def test_find_related_technology(self, client: LeakIXClient) -> None:
        """Test finding related targets by technology."""
        mock_data = {
            "services": [SAMPLE_SERVICE_EVENT],
            "leaks": [],
        }
        mock_search_results = [SAMPLE_SERVICE_EVENT]

        with (
            patch.object(
                client.api,
                "get_host",
                new_callable=AsyncMock,
            ) as mock_host,
            patch.object(
                client.api,
                "search",
                new_callable=AsyncMock,
            ) as mock_search,
        ):
            mock_host.return_value = _mock_response(mock_data)
            mock_search.return_value = _mock_response(mock_search_results)
            result = await client.find_related("192.168.1.1", "technology")

        assert result["relation_type"] == "technology"
        assert len(result["related"]) == 1
        assert "nginx" in result["search_query"]

    @pytest.mark.asyncio
    async def test_find_related_asn(self, client: LeakIXClient) -> None:
        """Test finding related targets by ASN."""
        mock_data = {
            "services": [SAMPLE_SERVICE_EVENT],
            "leaks": [],
        }

        with (
            patch.object(
                client.api,
                "get_host",
                new_callable=AsyncMock,
            ) as mock_host,
            patch.object(
                client.api,
                "search",
                new_callable=AsyncMock,
            ) as mock_search,
        ):
            mock_host.return_value = _mock_response(mock_data)
            mock_search.return_value = _mock_response([])
            result = await client.find_related("192.168.1.1", "asn")

        assert result["relation_type"] == "asn"
        assert "12345" in result["search_query"]

    @pytest.mark.asyncio
    async def test_find_related_no_services(self, client: LeakIXClient) -> None:
        """Test finding related with no services returns empty."""
        mock_data = {"services": [], "leaks": []}

        with patch.object(
            client.api, "get_host", new_callable=AsyncMock
        ) as mock:
            mock.return_value = _mock_response(mock_data)
            result = await client.find_related("192.168.1.1")

        assert result["related"] == []
