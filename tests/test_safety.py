from __future__ import annotations

import socket

import pytest

from kekmaxxing_mcp.safety import validate_public_url


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "http://localhost/",
        "http://[::1]/",
        "http://user:password@example.com/",
        "http://example.com:8080/",
    ],
)
def test_rejects_non_public_or_credentialed_urls(url: str) -> None:
    with pytest.raises(ValueError):
        validate_public_url(url)


def test_accepts_public_https(monkeypatch: pytest.MonkeyPatch) -> None:
    example_address = ".".join(str(part) for part in (93, 184, 216, 34))
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (example_address, 443))
        ],
    )
    target = validate_public_url("https://example.com/")
    assert target.hostname == "example.com"
    assert target.addresses == (example_address,)
