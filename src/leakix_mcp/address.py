"""Parsing and validation of server listen addresses.

A listen address has the form ``[host]:port``. The host may be omitted
(defaulting to ``0.0.0.0``), an IPv4 or IPv6 address, or a hostname. IPv6
literals must be bracketed so the port colon is unambiguous, e.g.
``[::1]:8080``.

The host is modelled as a sum type ``Host = IPv4Address | IPv6Address |
Hostname``: parsing injects a string into exactly one summand, so a
parsed host carries its kind in the type and illegal hosts are
unrepresentable.
"""

import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import NamedTuple, TypeAlias

MIN_PORT = 1
MAX_PORT = 65535

_MAX_HOSTNAME_LENGTH = 253
_HOSTNAME_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class AddressError(ValueError):
    """Base class for listen-address parsing errors."""


class MalformedAddressError(AddressError):
    """The string is not of the form ``host:port``."""

    def __init__(self, address: str, reason: str) -> None:
        self.address = address
        self.reason = reason
        super().__init__(f"Invalid address {address!r}: {reason}")


class InvalidHostError(AddressError):
    """The host is neither an IP address nor a valid hostname."""

    def __init__(self, host: str) -> None:
        self.host = host
        super().__init__(
            f"Invalid host {host!r}: expected an IP address or hostname"
        )


class InvalidPortError(AddressError):
    """The port is not a valid TCP port."""

    def __init__(self, port: str, reason: str) -> None:
        self.port = port
        self.reason = reason
        super().__init__(f"Invalid port {port!r}: {reason}")


class PortSyntaxError(InvalidPortError):
    """The port is not a decimal integer."""

    def __init__(self, port: str) -> None:
        super().__init__(port, "expected a decimal integer")


class PortRangeError(InvalidPortError):
    """The port is out of the range ``MIN_PORT``..``MAX_PORT``."""

    def __init__(self, port: str, value: int) -> None:
        self.value = value
        super().__init__(port, f"out of range (expected {MIN_PORT}-{MAX_PORT})")


def is_hostname(host: str) -> bool:
    """Return whether host is a valid RFC 1123 hostname.

    Enforces: a single optional trailing dot (the root); total length at
    most 253; one-to-63-character labels of letters, digits and hyphens,
    not starting or ending with a hyphen (RFC 1123 section 2.1, relaxing
    RFC 952 to allow a leading digit); and a top-level label that is not
    all-numeric, so the name cannot be read as a dotted-decimal address.
    """
    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > _MAX_HOSTNAME_LENGTH:
        return False
    labels = host.split(".")
    if not all(_HOSTNAME_LABEL.match(label) for label in labels):
        return False
    return not labels[-1].isdigit()


@dataclass(frozen=True, slots=True)
class Hostname:
    """A validated RFC 1123 hostname (lowercased)."""

    value: str

    def __post_init__(self) -> None:
        if not is_hostname(self.value):
            raise InvalidHostError(self.value)

    def __str__(self) -> str:
        return self.value


Host: TypeAlias = IPv4Address | IPv6Address | Hostname

DEFAULT_HOST: Host = IPv4Address("0.0.0.0")


def is_ip(host: Host) -> bool:
    """Return whether a parsed host is an IP address rather than a hostname.

    Discriminates the IPv4/IPv6 injections of the ``Host`` sum type from
    the ``Hostname`` injection.
    """
    return isinstance(host, IPv4Address | IPv6Address)


def parse_host(host: str) -> Host:
    """Parse host into an IPv4Address, IPv6Address, or Hostname.

    IP addresses are normalized by ``ipaddress``; hostnames are
    lowercased. Raises ValueError if host is neither.
    """
    try:
        return ip_address(host)
    except ValueError:
        return Hostname(host.lower())


def parse_port(port: str) -> int:
    """Parse a port string, requiring a decimal integer in range."""
    if not (port.isascii() and port.isdigit()):
        raise PortSyntaxError(port)
    value = int(port)
    if not MIN_PORT <= value <= MAX_PORT:
        raise PortRangeError(port, value)
    return value


class ServerAddress(NamedTuple):
    """A validated listen address."""

    host: Host
    port: int

    def __str__(self) -> str:
        if isinstance(self.host, IPv6Address):
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"


def _split(address: str) -> tuple[str, str]:
    """Split '[host]:port' into (host, port) strings."""
    if address.startswith("["):
        end = address.find("]")
        if end == -1:
            raise MalformedAddressError(address, "unmatched '['")
        host, rest = address[1:end], address[end + 1 :]
        if not rest.startswith(":"):
            raise MalformedAddressError(address, "expected [host]:port")
        return host, rest[1:]
    host, sep, port = address.rpartition(":")
    if not sep:
        raise MalformedAddressError(address, "expected host:port")
    if ":" in host:
        raise MalformedAddressError(
            address, "unbracketed IPv6 (use [host]:port)"
        )
    return host, port


def parse_address(address: str) -> ServerAddress:
    """Parse a listen address like '0.0.0.0:8080', ':8081' or '[::1]:80'."""
    host, port = _split(address)
    return ServerAddress(
        DEFAULT_HOST if host == "" else parse_host(host),
        parse_port(port),
    )
