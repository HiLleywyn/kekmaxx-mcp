from __future__ import annotations

import socket
from contextlib import contextmanager
from types import SimpleNamespace as NS
from unittest.mock import Mock

import httpx
import pytest

from kekmaxxing_mcp import browser, safety

PUBLIC = ".".join(map(str, [93, 184, 216, 34]))
PRIVATE = ".".join(map(str, [127, 0, 0, 1]))


def dns(monkeypatch, addresses):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443)) for address in addresses
        ],
    )


def test_dns_rebinding_checks_connection_time_and_pins_numeric_socket(monkeypatch):
    dns(monkeypatch, [PUBLIC])
    initial = safety.validate_public_url("https://example.org/")
    dns(monkeypatch, [PRIVATE])
    with pytest.raises(ValueError):
        safety.PublicBackend().connect_tcp(initial.hostname, 443)
    sock = Mock()
    sock.getpeername.return_value = (PUBLIC, 443)
    monkeypatch.setattr(socket, "socket", lambda *a: sock)
    safety.connect_pinned(initial)
    sock.connect.assert_called_once_with((PUBLIC, 443))


def test_mixed_dns_answers_and_peer_mismatch_fail(monkeypatch):
    dns(monkeypatch, [PUBLIC, PRIVATE])
    with pytest.raises(ValueError):
        safety.validate_public_url("https://example.org/")
    dns(monkeypatch, [PUBLIC])
    target = safety.validate_public_url("https://example.org/")
    sock = Mock()
    sock.getpeername.return_value = (PRIVATE, 443)
    monkeypatch.setattr(socket, "socket", lambda *a: sock)
    with pytest.raises(ValueError, match="peer"):
        safety.connect_pinned(target)
    sock.close.assert_called_once()


def fake_http(monkeypatch, handler):
    @contextmanager
    def client(*args, **kwargs):
        with httpx.Client(transport=httpx.MockTransport(handler)) as value:
            yield value

    monkeypatch.setattr(safety, "public_client", client)


def test_redirect_private_destination_and_decompression_budget(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, *a, **kw: [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                (PRIVATE if host == "localhost" else PUBLIC, 443),
            )
        ],
    )
    fake_http(monkeypatch, lambda r: httpx.Response(302, headers={"location": "http://localhost/"}))
    with pytest.raises(ValueError):
        safety.public_get("https://example.org/")
    import gzip

    fake_http(
        monkeypatch,
        lambda r: httpx.Response(
            200,
            headers={"content-encoding": "gzip"},
            stream=httpx.ByteStream(gzip.compress(b"x" * 5000)),
        ),
    )
    with pytest.raises(ValueError, match="exceeded"):
        safety.public_get("https://example.org/", max_bytes=100)


def test_retry_budget_and_credentials_rejected(monkeypatch):
    dns(monkeypatch, [PUBLIC])
    calls = []
    fake_http(
        monkeypatch,
        lambda r: (
            calls.append(r)
            or httpx.Response(429, headers={"retry-after": "0"}, stream=httpx.ByteStream(b""))
        ),
    )
    assert safety.public_get("https://example.org/", retries=1)[1] == 429
    assert len(calls) == 2
    with pytest.raises(ValueError):
        safety.public_get("https://example.org/", headers={"Authorization": "secret"})


def test_browser_subresources_redirects_forms_and_budget(monkeypatch):
    route = Mock()
    route.request = NS(method="GET", url="https://example.org/script.js")
    monkeypatch.setattr(
        browser,
        "public_get",
        lambda *a, **kw: (
            route.request.url,
            200,
            {"set-cookie": "discard", "content-type": "text/javascript"},
            b"ok",
        ),
    )
    budget = {"requests": 0, "bytes": 0}
    browser.guarded_route(route, budget)
    assert "set-cookie" not in route.fulfill.call_args.kwargs["headers"]
    route.request.method = "POST"
    browser.guarded_route(route, budget)
    route.abort.assert_called_once()
    route.reset_mock()
    route.request.method = "GET"
    monkeypatch.setattr(browser, "public_get", lambda *a, **kw: (_ for _ in ()).throw(ValueError()))
    browser.guarded_route(route, budget)
    route.abort.assert_called_once()
    route.reset_mock()
    budget["requests"] = 150
    browser.guarded_route(route, budget)
    route.abort.assert_called_once()
