"""Tests for leakix_mcp.address."""

from ipaddress import IPv4Address, IPv6Address

import pytest
from hypothesis import given
from hypothesis import strategies as st

from leakix_mcp.address import (
    MAX_PORT,
    MIN_PORT,
    AddressError,
    Host,
    Hostname,
    InvalidHostError,
    InvalidPortError,
    MalformedAddressError,
    PortRangeError,
    PortSyntaxError,
    ServerAddress,
    is_hostname,
    is_ip,
    parse_address,
    parse_host,
    parse_port,
)

# A label whose final component starts with a letter cannot be read as an
# IPv4/IPv6 literal, so a generated hostname stays in the Hostname summand.
_label = st.from_regex(r"[a-z0-9](?:[a-z0-9-]{0,20}[a-z0-9])?", fullmatch=True)
_tld = st.from_regex(r"[a-z](?:[a-z0-9-]{0,20}[a-z0-9])?", fullmatch=True)
_hostnames = st.builds(
    lambda labels, tld: Hostname(".".join([*labels, tld])),
    st.lists(_label, max_size=3),
    _tld,
)
_hosts: st.SearchStrategy[Host] = st.one_of(
    st.ip_addresses(v=4), st.ip_addresses(v=6), _hostnames
)
_ports = st.integers(MIN_PORT, MAX_PORT)


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("0.0.0.0:8080", ServerAddress(IPv4Address("0.0.0.0"), 8080)),
        ("127.0.0.1:80", ServerAddress(IPv4Address("127.0.0.1"), 80)),
        (":8081", ServerAddress(IPv4Address("0.0.0.0"), 8081)),
        ("EXAMPLE.com:1", ServerAddress(Hostname("example.com"), 1)),
        ("api.leakix.net:443", ServerAddress(Hostname("api.leakix.net"), 443)),
        ("[::1]:8080", ServerAddress(IPv6Address("::1"), 8080)),
        (
            "[2606:4700:4700:0:0:0:0:1111]:53",
            ServerAddress(IPv6Address("2606:4700:4700::1111"), 53),
        ),
        (
            "[::ffff:192.168.1.1]:443",
            ServerAddress(IPv6Address("::ffff:192.168.1.1"), 443),
        ),
    ],
)
def test_parse_address_valid(address: str, expected: ServerAddress) -> None:
    assert parse_address(address) == expected


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0:8080",
        "[::1]:8080",
        "[2606:4700:4700::1111]:53",
        "localhost:443",
    ],
)
def test_parse_address_str_roundtrip(address: str) -> None:
    assert str(parse_address(address)) == address.lower()


@pytest.mark.parametrize(
    ("address", "exc"),
    [
        ("8080", MalformedAddressError),
        ("localhost", MalformedAddressError),
        ("", MalformedAddressError),
        ("[::1:80", MalformedAddressError),
        ("[::1]8080", MalformedAddressError),
        ("::1:80", MalformedAddressError),
        ("2606:4700::1:80", MalformedAddressError),
        ("bad_host:80", InvalidHostError),
        ("-bad.example:80", InvalidHostError),
        ("[::gg]:80", InvalidHostError),
        ("999.999.999.999:80", InvalidHostError),
        ("12345:80", InvalidHostError),
        ("example.42:80", InvalidHostError),
        ("localhost:", PortSyntaxError),
        ("localhost:abc", PortSyntaxError),
        ("localhost:8_0", PortSyntaxError),
        ("localhost:８０", PortSyntaxError),
        ("localhost: 80", PortSyntaxError),
        ("localhost:+80", PortSyntaxError),
        ("localhost:-1", PortSyntaxError),
        ("localhost:0", PortRangeError),
        ("localhost:65536", PortRangeError),
    ],
)
def test_parse_address_errors(address: str, exc: type[AddressError]) -> None:
    with pytest.raises(exc) as info:
        parse_address(address)
    assert isinstance(info.value, AddressError)
    assert isinstance(info.value, ValueError)


def test_error_attributes() -> None:
    with pytest.raises(MalformedAddressError) as m:
        parse_address("::1:80")
    assert m.value.address == "::1:80"
    assert "unbracketed IPv6" in m.value.reason

    with pytest.raises(InvalidHostError) as h:
        parse_address("bad_host:80")
    assert h.value.host == "bad_host"

    with pytest.raises(PortRangeError) as p:
        parse_address("localhost:65536")
    assert p.value.port == "65536"
    assert p.value.value == 65536


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", IPv4Address("127.0.0.1")),
        ("::1", IPv6Address("::1")),
        ("2606:4700:4700:0:0:0:0:1111", IPv6Address("2606:4700:4700::1111")),
        ("LocalHost", Hostname("localhost")),
    ],
)
def test_parse_host(host: str, expected: object) -> None:
    result = parse_host(host)
    assert result == expected
    assert type(result) is type(expected)


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "example.com",
        "a.b.c.d.example.museum",
        "xn--nxasmq6b.example",
        "host-1.internal",
        "example.com.",
        "1host.example",
        "1.2.3.example",
    ],
)
def test_is_hostname_valid(host: str) -> None:
    assert is_hostname(host)


@pytest.mark.parametrize(
    "host",
    [
        "",
        "-leading.example",
        "trailing-.example",
        "under_score.example",
        "sp ace.example",
        "a" * 64 + ".example",
        "a." * 127 + "toolong",
        "999.999.999.999",
        "12345",
        "example.42",
        "a..b",
        "example.com..",
    ],
)
def test_is_hostname_invalid(host: str) -> None:
    assert not is_hostname(host)


def test_hostname_rejects_invalid() -> None:
    with pytest.raises(InvalidHostError):
        Hostname("bad_host")


@pytest.mark.parametrize("port", ["1", "80", "65535"])
def test_parse_port_valid(port: str) -> None:
    assert parse_port(port) == int(port)


@pytest.mark.parametrize(
    ("port", "exc"),
    [
        ("0", PortRangeError),
        ("65536", PortRangeError),
        ("abc", PortSyntaxError),
        ("8_0", PortSyntaxError),
        ("-1", PortSyntaxError),
        ("", PortSyntaxError),
    ],
)
def test_parse_port_invalid(port: str, exc: type[InvalidPortError]) -> None:
    with pytest.raises(exc):
        parse_port(port)


# --- Property-based tests: the algebraic laws of the parser ---


@given(host=_hosts)
def test_parse_host_is_a_section(host: Host) -> None:
    """parse_host(str(h)) == h: parsing is a right inverse of rendering
    on canonical hosts (a section of the underlying-value quotient)."""
    assert parse_host(str(host)) == host


@given(host=_hosts)
def test_normalize_is_idempotent(host: Host) -> None:
    """normalize = parse_host . str is idempotent: a retraction onto the
    canonical-forms subset."""
    once = parse_host(str(host))
    assert parse_host(str(once)) == once


@given(host=_hosts, port=_ports)
def test_parse_address_str_roundtrip_pbt(host: Host, port: int) -> None:
    """parse_address(str(addr)) == addr: (str, parse) is a retraction on
    valid addresses."""
    addr = ServerAddress(host, port)
    assert parse_address(str(addr)) == addr


@given(text=st.text())
def test_parse_address_only_raises_address_error(text: str) -> None:
    """Totality: on arbitrary input parse_address returns a ServerAddress
    or raises AddressError, never any other exception."""
    try:
        result = parse_address(text)
    except AddressError:
        return
    assert isinstance(result, ServerAddress)


# --- is_ip: the Host sum-type injection discriminator ---


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("::1", True),
        ("2606:4700:4700::1111", True),
        ("example.com", False),
        ("localhost", False),
    ],
)
def test_is_ip_discriminates_injection(host: str, expected: bool) -> None:
    assert is_ip(parse_host(host)) is expected
