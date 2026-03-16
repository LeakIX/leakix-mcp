"""Tests for the LeakIX client."""

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from l9format import l9format

from leakix_mcp.client import LeakIXClient, parse_l9event, parse_l9events

# Sample API response data (based on l9format schema)
SAMPLE_SERVICE_EVENT = {
    "event_type": "service",
    "event_source": "HttpPlugin",
    "event_pipeline": ["l9scan"],
    "event_fingerprint": "abc123",
    "ip": "192.168.1.1",
    "port": "80",
    "host": "example.com",
    "reverse": "example.com",
    "protocol": "http",
    "transport": ["tcp"],
    "summary": "HTTP Server",
    "time": "2026-01-15T10:30:00Z",
    "http": {
        "root": "/",
        "url": "http://example.com/",
        "status": 200,
        "length": 1234,
        "header": {"Server": "nginx"},
        "title": "Example Domain",
        "favicon_hash": "",
    },
    "ssh": {
        "fingerprint": "",
        "version": 0,
        "banner": "",
        "motd": "",
    },
    "service": {
        "credentials": {
            "noauth": False,
            "username": "",
            "password": "",
            "key": "",
        },
        "software": {
            "name": "nginx",
            "version": "1.18.0",
            "os": "Linux",
            "fingerprint": "",
        },
    },
    "geoip": {
        "continent_name": "North America",
        "country_name": "United States",
        "country_iso_code": "US",
        "city_name": "New York",
        "region_name": "New York",
        "region_iso_code": "NY",
        "location": {"lat": "40.7128", "lon": "-74.0060"},
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
    "event_pipeline": ["l9scan"],
    "event_fingerprint": "def456",
    "ip": "10.0.0.1",
    "port": "443",
    "host": "leaked.example.com",
    "reverse": "leaked.example.com",
    "protocol": "https",
    "transport": ["tcp", "tls"],
    "summary": "Exposed Git configuration",
    "time": "2026-01-15T11:00:00Z",
    "http": {
        "root": "/",
        "url": "https://leaked.example.com/.git/config",
        "status": 200,
        "length": 512,
        "header": {},
        "title": "",
        "favicon_hash": "",
    },
    "ssh": {
        "fingerprint": "",
        "version": 0,
        "banner": "",
        "motd": "",
    },
    "service": {
        "credentials": {
            "noauth": False,
            "username": "",
            "password": "",
            "key": "",
        },
        "software": {
            "name": "Apache",
            "version": "2.4",
            "os": "Linux",
            "fingerprint": "",
        },
    },
    "leak": {
        "stage": "open",
        "type": "config_leak",
        "severity": "high",
        "dataset": {
            "rows": 0,
            "files": 1,
            "size": 512,
            "collections": 0,
            "infected": False,
        },
    },
    "geoip": {
        "continent_name": "Europe",
        "country_name": "Germany",
        "country_iso_code": "DE",
        "city_name": "Berlin",
        "region_name": "Berlin",
        "region_iso_code": "BE",
        "location": {"lat": "52.5200", "lon": "13.4050"},
    },
    "network": {
        "organization_name": "Example Hosting",
        "asn": 54321,
        "network": "10.0.0.0/8",
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
    "version": "1.0.0",
}


def make_response(
    status_code: int,
    json_data: dict | list | None = None,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Create an httpx.Response with a mock request."""
    request = httpx.Request("GET", "https://leakix.net/test")
    content = b""
    if json_data is not None:
        content = json.dumps(json_data).encode()
    response = httpx.Response(
        status_code=status_code,
        request=request,
        headers=headers or {},
        content=content,
    )
    return response


class TestParseL9Event:
    """Tests for l9event parsing functions."""

    def test_parse_l9event_with_valid_data(self) -> None:
        """Test parsing a valid l9event dict."""
        result = parse_l9event(SAMPLE_SERVICE_EVENT)
        # Should return either L9Event or dict
        assert result is not None

    def test_parse_l9event_with_minimal_data(self) -> None:
        """Test parsing with minimal data returns something usable."""
        minimal = {"event_type": "service", "ip": "1.2.3.4"}
        result = parse_l9event(minimal)
        assert result is not None
        assert isinstance(result, (dict, l9format.L9Event))

    def test_parse_l9events_list(self) -> None:
        """Test parsing a list of events."""
        events = [SAMPLE_SERVICE_EVENT, SAMPLE_LEAK_EVENT]
        results = parse_l9events(events)
        assert len(results) == 2


class TestLeakIXClient:
    """Tests for the LeakIX API client."""

    @pytest.fixture
    def client(self) -> LeakIXClient:
        """Create a test client."""
        return LeakIXClient(api_key="test-api-key")

    @pytest.mark.asyncio
    async def test_search_services(self, client: LeakIXClient) -> None:
        """Test searching for services."""
        mock_response = make_response(200, [SAMPLE_SERVICE_EVENT])

        with patch.object(
            client, "_get_client", new_callable=AsyncMock
        ) as mock_get:
            mock_http_client = AsyncMock()
            mock_http_client.request = AsyncMock(return_value=mock_response)
            mock_get.return_value = mock_http_client

            results = await client.search("+port:80", scope="service")

            assert len(results) == 1
            mock_http_client.request.assert_called_once()

    @pytest.mark.asyncio
    async def test_search_leaks(self, client: LeakIXClient) -> None:
        """Test searching for leaks."""
        mock_response = make_response(200, [SAMPLE_LEAK_EVENT])

        with patch.object(
            client, "_get_client", new_callable=AsyncMock
        ) as mock_get:
            mock_http_client = AsyncMock()
            mock_http_client.request = AsyncMock(return_value=mock_response)
            mock_get.return_value = mock_http_client

            results = await client.search("+leak.severity:high", scope="leak")

            assert len(results) == 1
            mock_http_client.request.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_host(self, client: LeakIXClient) -> None:
        """Test getting host information."""
        mock_response = make_response(
            200,
            {"Services": [SAMPLE_SERVICE_EVENT], "Leaks": []},
        )

        with patch.object(
            client, "_get_client", new_callable=AsyncMock
        ) as mock_get:
            mock_http_client = AsyncMock()
            mock_http_client.request = AsyncMock(return_value=mock_response)
            mock_get.return_value = mock_http_client

            result = await client.get_host("192.168.1.1")

            assert "Services" in result
            assert "Leaks" in result
            assert len(result["Services"]) == 1

    @pytest.mark.asyncio
    async def test_get_domain(self, client: LeakIXClient) -> None:
        """Test getting domain information."""
        mock_response = make_response(
            200,
            {"Services": [SAMPLE_SERVICE_EVENT], "Leaks": [SAMPLE_LEAK_EVENT]},
        )

        with patch.object(
            client, "_get_client", new_callable=AsyncMock
        ) as mock_get:
            mock_http_client = AsyncMock()
            mock_http_client.request = AsyncMock(return_value=mock_response)
            mock_get.return_value = mock_http_client

            result = await client.get_domain("example.com")

            assert len(result["Services"]) == 1
            assert len(result["Leaks"]) == 1

    @pytest.mark.asyncio
    async def test_get_subdomains(self, client: LeakIXClient) -> None:
        """Test getting subdomains."""
        mock_response = make_response(200, [SAMPLE_SUBDOMAIN])

        with patch.object(
            client, "_get_client", new_callable=AsyncMock
        ) as mock_get:
            mock_http_client = AsyncMock()
            mock_http_client.request = AsyncMock(return_value=mock_response)
            mock_get.return_value = mock_http_client

            results = await client.get_subdomains("example.com")

            assert len(results) == 1
            assert results[0]["subdomain"] == "api.example.com"

    @pytest.mark.asyncio
    async def test_get_plugins(self, client: LeakIXClient) -> None:
        """Test getting available plugins."""
        mock_response = make_response(200, [SAMPLE_PLUGIN])

        with patch.object(
            client, "_get_client", new_callable=AsyncMock
        ) as mock_get:
            mock_http_client = AsyncMock()
            mock_http_client.request = AsyncMock(return_value=mock_response)
            mock_get.return_value = mock_http_client

            results = await client.get_plugins()

            assert len(results) == 1
            assert results[0]["name"] == "HttpPlugin"

    @pytest.mark.asyncio
    async def test_rate_limit_handling(self, client: LeakIXClient) -> None:
        """Test that rate limiting is handled."""
        rate_limited = make_response(
            429,
            None,
            headers={"x-limited-for": "100"},
        )
        success = make_response(200, [SAMPLE_SERVICE_EVENT])

        with patch.object(
            client, "_get_client", new_callable=AsyncMock
        ) as mock_get:
            mock_http_client = AsyncMock()
            mock_http_client.request = AsyncMock(
                side_effect=[rate_limited, success]
            )
            mock_get.return_value = mock_http_client

            with patch("asyncio.sleep", new_callable=AsyncMock):
                results = await client.search("+port:80")

            assert len(results) == 1
            # Should have been called twice due to rate limiting
            assert mock_http_client.request.call_count == 2

    @pytest.mark.asyncio
    async def test_empty_response_handling(self, client: LeakIXClient) -> None:
        """Test handling of empty responses."""
        mock_response = make_response(200, [])

        with patch.object(
            client, "_get_client", new_callable=AsyncMock
        ) as mock_get:
            mock_http_client = AsyncMock()
            mock_http_client.request = AsyncMock(return_value=mock_response)
            mock_get.return_value = mock_http_client

            results = await client.search("+nonexistent:query")

            assert results == []

    @pytest.mark.asyncio
    async def test_null_services_and_leaks(self, client: LeakIXClient) -> None:
        """Test handling of null Services/Leaks in host response."""
        mock_response = make_response(
            200,
            {"Services": None, "Leaks": None},
        )

        with patch.object(
            client, "_get_client", new_callable=AsyncMock
        ) as mock_get:
            mock_http_client = AsyncMock()
            mock_http_client.request = AsyncMock(return_value=mock_response)
            mock_get.return_value = mock_http_client

            result = await client.get_host("192.168.1.1")

            assert result["Services"] == []
            assert result["Leaks"] == []
