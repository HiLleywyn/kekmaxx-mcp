from __future__ import annotations

import json

import pytest

from kekmaxx_mcp import public_scan_archives
from kekmaxx_mcp.public_scan_archives import search_public_urlscan


def test_search_minimizes_public_scan_metadata(monkeypatch) -> None:
    payload = {
        "total": 1,
        "results": [
            {
                "submitter": {"country": "private-to-output"},
                "_id": "scan-1",
                "task": {
                    "uuid": "scan-1",
                    "time": "2026-10-13T00:00:00Z",
                    "visibility": "public",
                    "method": "api",
                    "url": "https://example.org/",
                },
                "page": {
                    "url": "https://example.org/",
                    "domain": "example.org",
                    "ip": "93.184.216.34",
                    "title": "Example",
                    "status": 200,
                    "asn": "AS15133",
                },
                "stats": {"requests": 5, "uniqIPs": 2, "uniqCountries": 1},
                "result": "https://urlscan.io/api/v1/result/scan-1/",
                "screenshot": "https://urlscan.io/screenshots/scan-1.png",
            }
        ],
    }

    def fake_get(url, *, max_bytes):
        assert url.startswith("https://urlscan.io/api/v1/search/")
        assert "domain%3Aexample.org" in url
        assert max_bytes == 10_000_000
        return url, 200, {"content-type": "application/json"}, json.dumps(payload).encode()

    monkeypatch.setattr(public_scan_archives, "public_get", fake_get)
    result = search_public_urlscan("domain:example.org", max_results=10)
    record = result["records"][0]
    assert result["returned_count"] == 1
    assert record["page_domain"] == "example.org"
    assert len(record["record_sha256"]) == 64
    assert "private-to-output" not in json.dumps(result)


def test_search_rejects_empty_or_excessive_queries() -> None:
    with pytest.raises(ValueError):
        search_public_urlscan("   ")
    with pytest.raises(ValueError):
        search_public_urlscan("x" * 501)
