"""Tests for the LeakIX MCP tools."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from leakix_mcp.tools import (
    exposure_report,
    find_related,
    helpers,
    quick_recon,
)

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


def _mock_response(data: object) -> MagicMock:
    """Create a mock AbstractResponse."""
    resp = MagicMock()
    resp.is_success.return_value = True
    resp.json.return_value = data
    return resp


def _mock_client(**methods: AsyncMock) -> MagicMock:
    """Create a mock AsyncClient with async methods."""
    client = MagicMock()
    for name, mock in methods.items():
        setattr(client, name, mock)
    return client


class TestHelpers:
    """Tests for helper functions."""

    def test_is_ip_valid(self) -> None:
        assert helpers.is_ip("192.168.1.1") is True
        assert helpers.is_ip("0.0.0.0") is True
        assert helpers.is_ip("255.255.255.255") is True

    def test_is_ip_invalid(self) -> None:
        assert helpers.is_ip("example.com") is False
        assert helpers.is_ip("256.1.1.1") is False
        assert helpers.is_ip("1.2.3") is False
        assert helpers.is_ip("") is False

    def test_get_field_dict(self) -> None:
        assert helpers.get_field({"name": "nginx"}, "name") == "nginx"
        assert helpers.get_field({"name": "nginx"}, "version") is None

    def test_get_field_none(self) -> None:
        assert helpers.get_field(None, "name") is None


class TestTools:
    """Tests for MCP tool handlers."""

    @pytest.mark.asyncio
    async def test_quick_recon_ip(self) -> None:
        mock_host = AsyncMock(
            return_value=_mock_response(
                {"services": [SAMPLE_SERVICE_EVENT], "leaks": []}
            )
        )
        client = _mock_client(get_host=mock_host)
        result = await quick_recon.handle(client, {"target": "192.168.1.1"})
        assert result["type"] == "ip"
        assert result["host"]["services"][0]["ip"] == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_quick_recon_domain(self) -> None:
        mock_domain_data = {
            "services": [SAMPLE_SERVICE_EVENT],
            "leaks": [SAMPLE_LEAK_EVENT],
        }
        client = _mock_client(
            get_domain=AsyncMock(return_value=_mock_response(mock_domain_data)),
            get_subdomains=AsyncMock(
                return_value=_mock_response([SAMPLE_SUBDOMAIN])
            ),
        )
        result = await quick_recon.handle(client, {"target": "example.com"})
        assert result["type"] == "domain"
        assert result["domain"] == mock_domain_data
        assert len(result["subdomains"]) == 1

    @pytest.mark.asyncio
    async def test_exposure_report_ip(self) -> None:
        mock_data = {
            "services": [SAMPLE_SERVICE_EVENT],
            "leaks": [SAMPLE_LEAK_EVENT],
        }
        client = _mock_client(
            get_host=AsyncMock(return_value=_mock_response(mock_data))
        )
        report = await exposure_report.handle(client, {"target": "192.168.1.1"})
        assert report["target"] == "192.168.1.1"
        assert report["summary"]["total_services"] == 1
        assert report["summary"]["total_leaks"] == 1
        assert 80 in report["summary"]["exposed_ports"]
        assert "nginx" in report["summary"]["technologies"]
        assert "United States" in report["summary"]["countries"]
        assert len(report["summary"]["critical_findings"]) == 1
        assert report["risk_level"] == "critical"

    @pytest.mark.asyncio
    async def test_exposure_report_no_leaks(self) -> None:
        mock_data = {
            "services": [SAMPLE_SERVICE_EVENT],
            "leaks": [],
        }
        client = _mock_client(
            get_host=AsyncMock(return_value=_mock_response(mock_data))
        )
        report = await exposure_report.handle(client, {"target": "192.168.1.1"})
        assert report["risk_level"] == "minimal"
        assert report["summary"]["total_leaks"] == 0

    @pytest.mark.asyncio
    async def test_exposure_report_empty(self) -> None:
        mock_data = {"services": [], "leaks": []}
        client = _mock_client(
            get_host=AsyncMock(return_value=_mock_response(mock_data))
        )
        report = await exposure_report.handle(client, {"target": "10.0.0.1"})
        assert report["risk_level"] == "minimal"
        assert report["summary"]["total_services"] == 0

    @pytest.mark.asyncio
    async def test_find_related_technology(self) -> None:
        mock_data = {
            "services": [SAMPLE_SERVICE_EVENT],
            "leaks": [],
        }
        client = _mock_client(
            get_host=AsyncMock(return_value=_mock_response(mock_data)),
            search=AsyncMock(
                return_value=_mock_response([SAMPLE_SERVICE_EVENT])
            ),
        )
        result = await find_related.handle(
            client, {"target": "192.168.1.1", "relation_type": "technology"}
        )
        assert result["relation_type"] == "technology"
        assert len(result["related"]) == 1
        assert "nginx" in result["search_query"]

    @pytest.mark.asyncio
    async def test_find_related_asn(self) -> None:
        mock_data = {
            "services": [SAMPLE_SERVICE_EVENT],
            "leaks": [],
        }
        client = _mock_client(
            get_host=AsyncMock(return_value=_mock_response(mock_data)),
            search=AsyncMock(return_value=_mock_response([])),
        )
        result = await find_related.handle(
            client, {"target": "192.168.1.1", "relation_type": "asn"}
        )
        assert result["relation_type"] == "asn"
        assert "12345" in result["search_query"]

    @pytest.mark.asyncio
    async def test_find_related_no_services(self) -> None:
        mock_data = {"services": [], "leaks": []}
        client = _mock_client(
            get_host=AsyncMock(return_value=_mock_response(mock_data))
        )
        result = await find_related.handle(client, {"target": "192.168.1.1"})
        assert result["related"] == []
