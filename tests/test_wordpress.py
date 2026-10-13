from __future__ import annotations

import json

import httpx
import pytest

from kekmaxxing_mcp import wordpress


def _public_target(url: str):
    class Target:
        hostname = "example.org"
        port = 443

        def __init__(self, value: str) -> None:
            self.url = value

    return Target(url)


def test_map_public_user_fingerprints_groups_cross_site_hashes(monkeypatch) -> None:
    fingerprint = "a" * 64
    payloads = {
        "alpha.example": [
            {
                "id": 1,
                "name": "Alice Local",
                "slug": "alice",
                "link": "https://alpha.example/author/alice/",
                "avatar_urls": {"96": f"https://secure.gravatar.com/avatar/{fingerprint}?s=96"},
            }
        ],
        "beta.example": [
            {
                "id": 2,
                "name": "Bob Local",
                "slug": "bob",
                "link": "https://beta.example/author/bob/",
                "avatar_urls": {"96": f"https://secure.gravatar.com/avatar/{fingerprint}?s=96"},
            }
        ],
    }

    def fake_validate(url: str):
        parsed = wordpress.urlparse(url)

        class Target:
            pass

        target = Target()
        target.url = url
        target.hostname = parsed.hostname
        target.port = 443
        return target

    def fake_get(url: str, **_kwargs):
        hostname = wordpress.urlparse(url).hostname
        return (
            url,
            200,
            {"content-type": "application/json"},
            json.dumps(payloads[hostname]).encode(),
        )

    monkeypatch.setattr(wordpress, "validate_public_url", fake_validate)
    monkeypatch.setattr(wordpress, "public_get", fake_get)
    result = wordpress.map_public_user_fingerprints(
        ["https://alpha.example", "https://beta.example/news"]
    )
    assert len(result["repeated_fingerprints"]) == 1
    assert result["repeated_fingerprints"][0]["avatar_hash"] == fingerprint
    assert {item["name"] for item in result["repeated_fingerprints"][0]["identities"]} == {
        "Alice Local",
        "Bob Local",
    }


def test_public_post_search_counts_reads_total_header(monkeypatch) -> None:
    monkeypatch.setattr(wordpress, "validate_public_url", _public_target)

    def fake_get(url: str, **_kwargs):
        return url, 200, {"x-wp-total": "321"}, b"[]"

    monkeypatch.setattr(wordpress, "public_get", fake_get)
    result = wordpress.public_post_search_counts(["https://example.org"], ["midterm"], 2026)
    assert result["rows"] == [
        {"site": "https://example.org", "term": "midterm", "year": 2026, "total": 321}
    ]


def test_public_post_search_counts_caps_request_matrix() -> None:
    with pytest.raises(ValueError, match="must not exceed"):
        wordpress.public_post_search_counts(
            [f"https://site-{index}.example" for index in range(11)],
            [f"term-{index}" for index in range(23)],
            2026,
        )


def test_public_recent_post_source_map_extracts_declared_sources(monkeypatch) -> None:
    monkeypatch.setattr(wordpress, "validate_public_url", _public_target)
    payload = [
        {
            "id": 7,
            "date": "2026-10-12T10:25:56",
            "modified": "2026-10-12T10:25:56",
            "author": 1,
            "link": "https://example.org/story/",
            "title": {"rendered": "A &amp; B"},
            "content": {
                "rendered": (
                    '<p>Visible story.</p><a href="https://source.example/item?id=7&token=x">'
                    "Источник</a><a href=\"/about\">About</a>"
                )
            },
        }
    ]

    def fake_get(url: str, **_kwargs):
        return url, 200, {"x-wp-total": "1"}, json.dumps(payload).encode()

    monkeypatch.setattr(wordpress, "public_get", fake_get)
    result = wordpress.public_recent_post_source_map(["https://example.org"], per_site=1)
    row = result["posts"][0]
    assert row["title"] == "A & B"
    assert row["declared_source_links"] == [
        {"url": "https://source.example/item", "host": "source.example", "label": "Источник"}
    ]
    assert result["source_host_summary"] == [
        {
            "site": "https://example.org",
            "source_hosts": [{"host": "source.example", "linked_posts": 1}],
        }
    ]


def test_public_recent_post_source_map_caps_posts() -> None:
    with pytest.raises(ValueError, match="per_site"):
        wordpress.public_recent_post_source_map(["https://example.org"], per_site=101)
    with pytest.raises(ValueError, match="page"):
        wordpress.public_recent_post_source_map(["https://example.org"], page=11)


def test_map_public_site_identities_groups_exact_signals(monkeypatch) -> None:
    fingerprint = "b" * 64
    pages = {
        "alpha.example": b"""
            <html><head><title>Alpha</title><meta name="generator" content="WordPress 7.1">
            <script>gtag('config', 'G-ABC1234567');</script>
            <link href="/wp-content/themes/flatsome/style.css">
            <script src="/wp-content/plugins/woocommerce/app.js"></script></head>
            <body><a href="https://shared.example/contact">Contact</a></body></html>
        """,
        "beta.example": b"""
            <html><head><title>Beta</title><meta name="generator" content="WordPress 7.1">
            <script>gtag('config', 'G-ABC1234567');</script>
            <link href="/wp-content/themes/flatsome/style.css">
            <script src="/wp-content/plugins/woocommerce/app.js"></script></head>
            <body><a href="https://shared.example/returns">Returns</a></body></html>
        """,
    }

    def fake_validate(url: str):
        parsed = wordpress.urlparse(url)

        class Target:
            pass

        target = Target()
        target.url = url
        target.hostname = parsed.hostname
        target.port = 443
        return target

    def fake_get(url: str, **_kwargs):
        parsed = wordpress.urlparse(url)
        if parsed.path.startswith("/wp-json/"):
            payload = [
                {
                    "id": 1,
                    "name": "Public Author",
                    "slug": "author",
                    "link": f"https://{parsed.hostname}/author/author/",
                    "avatar_urls": {
                        "96": f"https://secure.gravatar.com/avatar/{fingerprint}?s=96"
                    },
                }
            ]
            return url, 200, {"content-type": "application/json"}, json.dumps(payload).encode()
        return url, 200, {"content-type": "text/html"}, pages[parsed.hostname]

    monkeypatch.setattr(wordpress, "validate_public_url", fake_validate)
    monkeypatch.setattr(wordpress, "public_get", fake_get)
    result = wordpress.map_public_site_identities(
        ["https://alpha.example", "https://beta.example"]
    )
    assert result["repeated_ga4_measurement_ids"] == [
        {
            "measurement_id": "G-ABC1234567",
            "sites": ["https://alpha.example", "https://beta.example"],
        }
    ]
    assert result["repeated_avatar_hashes"][0]["avatar_hash"] == fingerprint
    assert result["repeated_wordpress_stacks"][0]["sites"] == [
        "https://alpha.example",
        "https://beta.example",
    ]
    assert result["repeated_linked_hosts"] == [
        {
            "linked_host": "shared.example",
            "sites": ["https://alpha.example", "https://beta.example"],
        }
    ]


def test_map_public_site_identities_preserves_network_failure(monkeypatch) -> None:
    def fake_validate(url: str):
        parsed = wordpress.urlparse(url)

        class Target:
            pass

        target = Target()
        target.url = url
        target.hostname = parsed.hostname
        target.port = 443
        return target

    def fake_get(url: str, **_kwargs):
        parsed = wordpress.urlparse(url)
        if parsed.hostname == "slow.example":
            raise httpx.ConnectTimeout("timed out")
        if parsed.path.startswith("/wp-json/"):
            return url, 200, {"content-type": "application/json"}, b"[]"
        return url, 200, {"content-type": "text/html"}, b"<title>Live</title>"

    monkeypatch.setattr(wordpress, "validate_public_url", fake_validate)
    monkeypatch.setattr(wordpress, "public_get", fake_get)
    result = wordpress.map_public_site_identities(
        ["https://slow.example", "https://live.example"]
    )
    assert [site["site"] for site in result["sites"]] == ["https://live.example"]
    assert result["failures"] == [{"site": "https://slow.example", "error": "timed out"}]


def test_map_public_site_identities_does_not_group_empty_non_wordpress_stacks(
    monkeypatch,
) -> None:
    def fake_validate(url: str):
        parsed = wordpress.urlparse(url)

        class Target:
            pass

        target = Target()
        target.url = url
        target.hostname = parsed.hostname
        target.port = 443
        return target

    def fake_get(url: str, **_kwargs):
        parsed = wordpress.urlparse(url)
        if parsed.path.startswith("/wp-json/"):
            return url, 404, {"content-type": "text/html"}, b"not wordpress"
        return url, 200, {"content-type": "text/html"}, b"<title>Plain site</title>"

    monkeypatch.setattr(wordpress, "validate_public_url", fake_validate)
    monkeypatch.setattr(wordpress, "public_get", fake_get)
    result = wordpress.map_public_site_identities(
        ["https://alpha.example", "https://beta.example"]
    )

    assert all(site["wordpress"]["stack_sha256"] is None for site in result["sites"])
    assert result["repeated_wordpress_stacks"] == []


def test_map_public_checkout_identities_reads_gateway_markers(monkeypatch) -> None:
    def fake_validate(url: str):
        parsed = wordpress.urlparse(url)

        class Target:
            pass

        target = Target()
        target.url = url
        target.hostname = parsed.hostname
        target.port = 443
        return target

    monkeypatch.setattr(wordpress, "validate_public_url", fake_validate)

    def fake_get(url: str, **_kwargs):
        body = (
            b'<link href="/wp-content/plugins/cardsshield-gateway-stripe/assets/styles.css">'
            b'<script src="/wp-content/plugins/cardsshield-gateway-stripe/assets/js/'
            b'checkout_hook.js?ver=2.6.6"></script>'
            b'<div class="payment_method_eh_paypal_express"></div>'
        )
        return url, 200, {"content-type": "text/html"}, body

    monkeypatch.setattr(wordpress, "public_get", fake_get)
    result = wordpress.map_public_checkout_identities(
        ["https://alpha.example", "https://beta.example"]
    )
    assert len(result["sites"]) == 2
    assert all(site["payment_markers"]["cardsshield_gateway_stripe"] for site in result["sites"])
    assert all(site["payment_markers"]["paypal_express"] for site in result["sites"])
    assert all(
        site["payment_markers"]["cardsshield_versions"] == ["2.6.6"]
        for site in result["sites"]
    )
    assert result["repeated_checkout_plugins"] == [
        {
            "plugin": "cardsshield-gateway-stripe",
            "sites": ["https://alpha.example", "https://beta.example"],
        }
    ]
