"""Policy link checks, with protection against server-side request forgery.

The service fetches URLs supplied by callers, so every request it makes is
checked first:

* only HTTPS, including after every redirect;
* the host must resolve only to public internet addresses, so private
  networks, localhost and cloud metadata endpoints are refused;
* redirects are followed manually, at most MAX_REDIRECTS hops, and each
  hop is checked again;
* response bodies are never downloaded.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Literal

import httpx

import config

LinkStatus = Literal["reachable", "unreachable", "blocked", "not checked"]

UNRESOLVABLE = "Host could not be resolved"


def _result(
    status: LinkStatus, status_code: int | None = None, error: str | None = None
) -> dict[str, Any]:
    reachable = {"reachable": True, "not checked": None}.get(status, False)
    return {
        "status": status,
        "reachable": reachable,
        "status_code": status_code,
        "error": error,
    }


def resolve_host(host: str) -> list[str]:
    """Return every IP address the host resolves to."""
    infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def is_public_address(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])  # drop IPv6 zone id
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def blocked_reason(url: httpx.URL) -> str | None:
    """Why this URL must not be fetched, or None if it is safe."""
    if url.scheme != "https":
        return "Only HTTPS links are checked"
    if not url.host:
        return "Link has no host"
    try:
        addresses = resolve_host(url.host)
    except (socket.gaierror, UnicodeError):
        return UNRESOLVABLE
    if not addresses or not all(is_public_address(a) for a in addresses):
        return "Host resolves to a private or reserved network address"
    return None


def http_link_checker(link: str) -> dict[str, Any]:
    """Check that a policy link responds, without leaving the public internet."""
    url = httpx.URL(link)
    try:
        with httpx.Client(timeout=config.LINK_TIMEOUT_SECONDS, follow_redirects=False) as client:
            for _ in range(config.MAX_REDIRECTS + 1):
                reason = blocked_reason(url)
                if reason == UNRESOLVABLE:  # a broken link, not a security refusal
                    return _result("unreachable", error=reason)
                if reason:
                    return _result("blocked", error=reason)

                response = client.head(url)
                if response.status_code in (405, 501):  # HEAD not supported
                    with client.stream("GET", url) as streamed:  # headers only
                        response = streamed

                if response.is_redirect and "location" in response.headers:
                    url = url.join(response.headers["location"])
                    continue

                if response.status_code < 400:
                    return _result("reachable", response.status_code)
                return _result("unreachable", response.status_code)

            return _result("unreachable", error="Too many redirects")
    except httpx.HTTPError as exc:
        return _result("unreachable", error=type(exc).__name__)


def skipped_link_checker(link: str) -> dict[str, Any]:
    return _result("not checked")
