"""End-to-end tests driving the real MCP server over the SDK's in-memory
transport.

Only the external boundary (the LeakIX AsyncClient, i.e. the leakix.net
endpoint) is faked: `server.get_client` is patched with a mock whose
methods return canned leakix.net JSON. Everything else runs for real: the
MCP protocol, input-schema validation, argument parsing, error surfacing,
and result serialization.

Responses, clients, and sessions are produced by factory fixtures (fixture
generators) so each test builds exactly the leakix.net payloads it needs
from fresh data.
"""

import json
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from leakix import Scope
from mcp import Client as MCPClient
from mcp.types import TextContent

import leakix_mcp.server as server_module
from leakix_mcp.server import server

# Factory-fixture type aliases.
Response = Callable[..., Any]
Client = Callable[..., Any]
OkMethod = Callable[[Any], AsyncMock]
SessionFor = Callable[[Any], AbstractAsyncContextManager[MCPClient]]
CallTool = Callable[[Any, str, dict[str, Any]], Awaitable[Any]]


# --- Faked-response / client / session factory fixtures ---


@pytest.fixture
def response() -> Response:
    """Factory: wrap data in a faked leakix.net response object."""

    def _make(data: Any, *, success: bool = True, status: int = 200) -> Any:
        resp = MagicMock()
        resp.is_success.return_value = success
        resp.status_code.return_value = status
        resp.json.return_value = data
        return resp

    return _make


@pytest.fixture
def ok(response: Response) -> OkMethod:
    """Factory: an async client method returning a successful response."""

    def _make(data: Any) -> AsyncMock:
        return AsyncMock(return_value=response(data))

    return _make


@pytest.fixture
def client() -> Client:
    """Factory: a mock AsyncClient from name->async-method mappings."""

    def _make(**methods: AsyncMock) -> Any:
        mock = MagicMock()
        for name, method in methods.items():
            setattr(mock, name, method)
        return mock

    return _make


@pytest.fixture
def session_for(monkeypatch: pytest.MonkeyPatch) -> SessionFor:
    """Factory: a live MCP session whose leakix client is the given mock."""

    @asynccontextmanager
    async def _open(mock_client: Any) -> AsyncIterator[MCPClient]:
        monkeypatch.setattr(server_module, "get_client", lambda: mock_client)
        async with MCPClient(server) as session:
            yield session

    return _open


@pytest.fixture
def call(session_for: SessionFor) -> CallTool:
    """Factory: call a tool over a live session and return the result."""

    async def _call(
        mock_client: Any, name: str, arguments: dict[str, Any]
    ) -> Any:
        async with session_for(mock_client) as session:
            return await session.call_tool(name, arguments)

    return _call


# --- Faked leakix.net payload fixtures (fresh per test) ---


@pytest.fixture
def service() -> dict[str, Any]:
    return {
        "ip": "1.2.3.4",
        "port": "80",
        "service": {"software": {"name": "nginx", "version": "1.18.0"}},
        "geoip": {"country_name": "France"},
        "network": {"asn": 12345, "network": "1.0.0.0/8"},
    }


@pytest.fixture
def leak() -> dict[str, Any]:
    return {
        "event_source": "GitConfigHttpPlugin",
        "host": "leaked.example.com",
        "leak": {"severity": "high", "type": "config_leak"},
    }


@pytest.fixture
def subdomain() -> dict[str, Any]:
    return {"subdomain": "api.example.com", "distinct_ips": ["1.2.3.4"]}


@pytest.fixture
def plugin() -> dict[str, Any]:
    return {
        "name": "GitConfigHttpPlugin",
        "description": "Detects exposed .git/config files.",
    }


@pytest.fixture
def host_data(service: dict[str, Any], leak: dict[str, Any]) -> dict[str, Any]:
    return {"services": [service], "leaks": [leak]}


# --- Helpers ---


def _text(result: Any) -> str:
    """Concatenate the text of a CallToolResult's content blocks."""
    return "".join(b.text for b in result.content if isinstance(b, TextContent))


def _payload(result: Any) -> Any:
    """Assert success and return the parsed JSON body of a tool result."""
    assert result.is_error is False, _text(result)
    return json.loads(_text(result))


# --- Per-tool e2e tests ---


async def test_tool_search_leaks(
    client: Client, ok: OkMethod, call: CallTool, leak: dict[str, Any]
) -> None:
    c = client(search=ok([leak]))
    result = await call(c, "search_leaks", {"query": "+leak.severity:high"})
    assert _payload(result)[0]["leak"]["severity"] == "high"
    c.search.assert_awaited_once_with(
        "+leak.severity:high", scope=Scope.LEAK, page=0
    )


async def test_tool_search_services(
    client: Client, ok: OkMethod, call: CallTool, service: dict[str, Any]
) -> None:
    c = client(search=ok([service]))
    result = await call(c, "search_services", {"query": "+port:80", "page": 2})
    assert _payload(result)[0]["service"]["software"]["name"] == "nginx"
    c.search.assert_awaited_once_with("+port:80", scope=Scope.SERVICE, page=2)


async def test_tool_host_lookup(
    client: Client, ok: OkMethod, call: CallTool, host_data: dict[str, Any]
) -> None:
    c = client(get_host=ok(host_data))
    result = await call(c, "host_lookup", {"ip": "1.2.3.4"})
    assert _payload(result)["services"][0]["ip"] == "1.2.3.4"
    c.get_host.assert_awaited_once_with("1.2.3.4")


async def test_tool_domain_lookup(
    client: Client, ok: OkMethod, call: CallTool, host_data: dict[str, Any]
) -> None:
    c = client(get_domain=ok(host_data))
    result = await call(c, "domain_lookup", {"domain": "example.com"})
    assert _payload(result)["leaks"][0]["event_source"] == "GitConfigHttpPlugin"
    c.get_domain.assert_awaited_once_with("example.com")


async def test_tool_list_subdomains(
    client: Client, ok: OkMethod, call: CallTool, subdomain: dict[str, Any]
) -> None:
    c = client(get_subdomains=ok([subdomain]))
    result = await call(c, "list_subdomains", {"domain": "example.com"})
    assert _payload(result)[0]["subdomain"] == "api.example.com"
    c.get_subdomains.assert_awaited_once_with("example.com")


async def test_tool_list_plugins(
    client: Client, ok: OkMethod, call: CallTool, plugin: dict[str, Any]
) -> None:
    c = client(get_plugins=ok([plugin]))
    result = await call(c, "list_plugins", {})
    assert _payload(result)[0]["name"] == "GitConfigHttpPlugin"
    c.get_plugins.assert_awaited_once_with()


async def test_tool_bulk_export(
    client: Client, ok: OkMethod, call: CallTool, leak: dict[str, Any]
) -> None:
    c = client(bulk_export=ok([{"ip": "1.2.3.4", "events": [leak]}]))
    result = await call(
        c, "bulk_export", {"query": "+plugin:GitConfigHttpPlugin"}
    )
    assert _payload(result)[0]["ip"] == "1.2.3.4"
    query_arg = c.bulk_export.call_args.kwargs["queries"][0]
    assert query_arg.raw_q == "+plugin:GitConfigHttpPlugin"


async def test_tool_quick_recon_ip(
    client: Client, ok: OkMethod, call: CallTool, host_data: dict[str, Any]
) -> None:
    c = client(get_host=ok(host_data))
    payload = _payload(await call(c, "quick_recon", {"target": "1.2.3.4"}))
    assert payload["type"] == "ip"
    assert payload["host"] == host_data
    c.get_host.assert_awaited_once_with("1.2.3.4")


async def test_tool_quick_recon_domain(
    client: Client,
    ok: OkMethod,
    call: CallTool,
    host_data: dict[str, Any],
    subdomain: dict[str, Any],
) -> None:
    c = client(get_domain=ok(host_data), get_subdomains=ok([subdomain]))
    payload = _payload(await call(c, "quick_recon", {"target": "example.com"}))
    assert payload["type"] == "domain"
    assert payload["domain"] == host_data
    assert payload["subdomains"][0]["subdomain"] == "api.example.com"


async def test_tool_find_related(
    client: Client,
    ok: OkMethod,
    call: CallTool,
    host_data: dict[str, Any],
    service: dict[str, Any],
) -> None:
    c = client(get_host=ok(host_data), search=ok([service]))
    payload = _payload(
        await call(
            c,
            "find_related",
            {"target": "1.2.3.4", "relation_type": "technology"},
        )
    )
    assert payload["search_query"] == '+service.software.name:"nginx"'
    assert len(payload["related"]) == 1
    c.search.assert_awaited_once_with(
        '+service.software.name:"nginx"', scope=Scope.SERVICE, page=0
    )


async def test_tool_exposure_report(
    client: Client, ok: OkMethod, call: CallTool, host_data: dict[str, Any]
) -> None:
    payload = _payload(
        await call(
            client(get_host=ok(host_data)),
            "exposure_report",
            {"target": "1.2.3.4"},
        )
    )
    assert payload["target"] == "1.2.3.4"
    assert payload["summary"]["total_services"] == 1
    assert 80 in payload["summary"]["exposed_ports"]
    assert "nginx" in payload["summary"]["technologies"]
    assert payload["risk_level"] == "critical"


# --- Protocol, validation, and error surfacing ---


async def test_list_tools(client: Client, session_for: SessionFor) -> None:
    async with session_for(client()) as session:
        result = await session.list_tools()
    names = {t.name for t in result.tools}
    assert len(result.tools) == 10
    assert {"host_lookup", "search_leaks", "exposure_report"} <= names
    host = next(t for t in result.tools if t.name == "host_lookup")
    assert host.input_schema["required"] == ["ip"]


async def test_api_failure_is_error(
    client: Client, response: Response, call: CallTool
) -> None:
    """A failed leakix.net call is reported as isError, not empty success."""
    c = client(
        get_host=AsyncMock(
            return_value=response(
                {"error": "rate limited"}, success=False, status=429
            )
        )
    )
    result = await call(c, "host_lookup", {"ip": "1.2.3.4"})
    assert result.is_error is True
    assert "429" in _text(result)


async def test_invalid_args_is_error(client: Client, call: CallTool) -> None:
    """A non-IP for host_lookup is rejected by the pydantic validator."""
    c = client(get_host=AsyncMock())
    result = await call(c, "host_lookup", {"ip": "example.com"})
    assert result.is_error is True
    c.get_host.assert_not_awaited()


async def test_missing_required_is_error(
    client: Client, call: CallTool
) -> None:
    """A call missing a required argument is rejected, not silently run."""
    result = await call(client(), "search_leaks", {})
    assert result.is_error is True


async def test_resources(client: Client, session_for: SessionFor) -> None:
    async with session_for(client()) as session:
        listed = await session.list_resources()
        uris = {str(r.uri) for r in listed.resources}
        assert "leakix://skills.md" in uris
        read = await session.read_resource("leakix://skills.md")
    text = "".join(getattr(c, "text", "") for c in read.contents)
    assert text.strip() != ""
