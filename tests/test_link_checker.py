"""Link checking, including server-side request forgery (SSRF) protection."""

import socket

import httpx
import pytest

import link_checker

# Capture the real checker before the autouse fixture swaps in a stub.
check = link_checker.http_link_checker

PUBLIC_IP = "93.184.215.14"

DNS = {
    "policies.example.com": [PUBLIC_IP],
    "other.example.com": [PUBLIC_IP],
    "intranet.example.com": ["10.0.0.5"],
    "mixed.example.com": [PUBLIC_IP, "192.168.1.10"],
    "localhost": ["127.0.0.1"],
}


class Requests(list):
    """URLs the fake web server received, plus its routing table."""


@pytest.fixture
def web(monkeypatch):
    """Fake DNS and a fake web server; returns the list of URLs requested."""
    requested = Requests()

    def resolve(host):
        if host in DNS:
            return DNS[host]
        try:
            socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
            return [host]  # IP literal
        except OSError:
            raise socket.gaierror("unknown host") from None

    routes = {}

    def handler(request):
        requested.append(str(request.url))
        route = routes.get(
            (request.method, str(request.url)),
            routes.get(str(request.url), httpx.Response(200)),
        )
        if callable(route):
            return route(request)
        return httpx.Response(route.status_code, headers=route.headers)  # fresh copy

    monkeypatch.setattr(link_checker, "resolve_host", resolve)
    real_client = httpx.Client
    monkeypatch.setattr(
        link_checker.httpx,
        "Client",
        lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw),
    )
    requested.routes = routes
    return requested


# ---- address rules -------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",  # private
        "127.0.0.1",
        "::1",  # loopback
        "169.254.169.254",  # cloud metadata / link-local
        "100.64.0.1",  # carrier-grade NAT
        "0.0.0.0",
        "224.0.0.1",  # unspecified, multicast
        "fc00::1",
        "fe80::1",  # IPv6 private, link-local
        "::ffff:10.0.0.1",  # IPv4-mapped IPv6
    ],
)
def test_non_public_addresses_are_refused(address):
    assert link_checker.is_public_address(address) is False


@pytest.mark.parametrize("address", [PUBLIC_IP, "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(address):
    assert link_checker.is_public_address(address) is True


# ---- blocking ------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://intranet.example.com/policy",
        "https://localhost/policy",
        "https://169.254.169.254/latest/meta-data/",
        "https://[::1]/policy",
        "https://mixed.example.com/policy",  # any private address blocks
    ],
)
def test_private_destinations_are_blocked_without_a_request(web, url):
    result = check(url)
    assert result["status"] == "blocked"
    assert result["reachable"] is False
    assert web == []


def test_unresolvable_host_is_unreachable(web):
    result = check("https://no-such-host.invalid/policy")
    assert result == {
        "status": "unreachable",
        "reachable": False,
        "status_code": None,
        "error": "Host could not be resolved",
    }


def test_redirect_to_http_is_blocked(web):
    web.routes["https://policies.example.com/p"] = httpx.Response(
        302, headers={"location": "http://169.254.169.254/latest/meta-data/"}
    )
    result = check("https://policies.example.com/p")
    assert result["status"] == "blocked"
    assert result["error"] == "Only HTTPS links are checked"
    assert web == ["https://policies.example.com/p"]


def test_redirect_to_private_host_is_blocked(web):
    web.routes["https://policies.example.com/p"] = httpx.Response(
        301, headers={"location": "https://intranet.example.com/secret"}
    )
    result = check("https://policies.example.com/p")
    assert result["status"] == "blocked"
    assert web == ["https://policies.example.com/p"]


def test_safe_redirect_is_followed(web):
    web.routes["https://policies.example.com/p"] = httpx.Response(
        301, headers={"location": "https://other.example.com/policy"}
    )
    result = check("https://policies.example.com/p")
    assert result["status"] == "reachable" and result["status_code"] == 200
    assert web == ["https://policies.example.com/p", "https://other.example.com/policy"]


def test_relative_redirect_is_resolved(web):
    web.routes["https://policies.example.com/old"] = httpx.Response(
        302, headers={"location": "/new"}
    )
    assert check("https://policies.example.com/old")["status"] == "reachable"
    assert web[-1] == "https://policies.example.com/new"


def test_redirect_loop_stops(web):
    web.routes["https://policies.example.com/loop"] = httpx.Response(
        302, headers={"location": "/loop"}
    )
    result = check("https://policies.example.com/loop")
    assert result["status"] == "unreachable"
    assert result["error"] == "Too many redirects"
    assert len(web) == link_checker.config.MAX_REDIRECTS + 1


# ---- responses -----------------------------------------------------------


def test_missing_page_is_unreachable(web):
    web.routes["https://policies.example.com/missing"] = httpx.Response(404)
    result = check("https://policies.example.com/missing")
    assert result == {
        "status": "unreachable",
        "reachable": False,
        "status_code": 404,
        "error": None,
    }


def test_head_not_allowed_falls_back_to_get_without_downloading(web):
    downloaded = []

    def body():
        downloaded.append(True)
        yield b"x" * 10_000_000

    url = "https://policies.example.com/no-head"
    web.routes[("HEAD", url)] = httpx.Response(405)
    web.routes[("GET", url)] = lambda request: httpx.Response(200, content=body())
    result = check(url)
    assert result["status"] == "reachable" and result["status_code"] == 200
    assert downloaded == []


def test_network_error_is_unreachable(web):
    def fail(request):
        raise httpx.ConnectError("boom", request=request)

    web.routes["https://policies.example.com/down"] = fail
    result = check("https://policies.example.com/down")
    assert result["status"] == "unreachable" and result["error"] == "ConnectError"


def test_skipped_checker_reports_not_checked():
    assert link_checker.skipped_link_checker("https://x.example.com") == {
        "status": "not checked",
        "reachable": None,
        "status_code": None,
        "error": None,
    }
