"""SSRF guard — the P0 (scan-api-spec §4, S1-S6.1).

A service that dials user-supplied URLs is an SSRF weapon: aimed at the cloud
metadata endpoint (169.254.169.254) or an internal host it leaks credentials or
pivots into the VPC. The engine deliberately omits this check (it is
transport-agnostic and unit-tested offline); it lives here, and runs **before**
any socket is opened (S6).

Classification is by *routability*, not a hand-maintained string allowlist: an
address is blocked iff it is not globally routable (`ipaddress.is_global` is
False) — which covers link-local, loopback, RFC-1918, IPv6 ULA/link-local,
unspecified, multicast and reserved in one rule (S1-S3.1). IPv4-mapped IPv6
(`::ffff:a.b.c.d`) is unwrapped first so a mapped metadata IP cannot slip
through. DNS is resolved via an injected resolver and *every* returned address
is checked — any blocked address fails the whole target closed (S4/S6.1).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Sequence
from urllib.parse import urlsplit

from .errors import BlockedTarget, InvalidTarget

# host -> resolved IP strings. Injected so unit tests need no real DNS.
Resolver = Callable[[str], Sequence[str]]


def is_blocked(ip_str: str) -> bool:
    """True iff `ip_str` is not a globally-routable public address (S1-S3.1)."""
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(ip_str)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # unwrap ::ffff:169.254.169.254 → 169.254.169.254
    return not ip.is_global


def parse_target(url: str) -> str:
    """Return the hostname of an absolute http(s) URL, or raise InvalidTarget (A3)."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise InvalidTarget("target must be an absolute http(s) URL with a host")
    return parts.hostname


def resolve_and_validate(url: str, resolver: Resolver) -> None:
    """Resolve `url`'s host and block if any resolved address is non-public.

    Raises InvalidTarget (unresolvable / unparseable) or BlockedTarget (a
    private/metadata/non-public address). Returns None when the target is safe.
    """
    host = parse_target(url)
    try:
        ipaddress.ip_address(host)  # literal IP target — classify directly, no DNS
        addresses: list[str] = [host]
    except ValueError:
        try:
            addresses = list(resolver(host))
        except OSError as exc:
            raise InvalidTarget("target host could not be resolved") from exc
        if not addresses:
            raise InvalidTarget("target host could not be resolved")

    for addr in addresses:
        try:
            blocked = is_blocked(addr)
        except ValueError as exc:
            raise InvalidTarget("target resolved to an unparseable address") from exc
        if blocked:
            # E6: do not echo the resolved internal address back to the caller.
            raise BlockedTarget("target resolves to a non-public address")
