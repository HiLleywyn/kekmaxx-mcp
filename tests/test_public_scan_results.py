from __future__ import annotations

from kekmaxxing_mcp import public_scan_results
from kekmaxxing_mcp.public_scan_results import inspect_public_urlscan_result


def test_result_extracts_only_named_host_and_drops_query_values(monkeypatch) -> None:
    html = b"""
    <html><head><title>Example - urlscan.io</title></head><body>
      <a href="https://web.archive.org/web/*/https://grop.net/22/abc?uid=secret&amp;x=1">
        archive
      </a>
      <a href="https://web.archive.org/web/*/https://unrelated.example/private?token=value">
        other
      </a>
    </body></html>
    """

    def fake_get(url, *, max_bytes):
        assert url.endswith("/01a132ef-f666-7119-8739-4d9058646ff2/")
        assert max_bytes == 25_000_000
        return url, 200, {"content-type": "text/html"}, html

    monkeypatch.setattr(public_scan_results, "public_get", fake_get)
    result = inspect_public_urlscan_result(
        "01a132ef-f666-7119-8739-4d9058646ff2", ["grop.net"]
    )
    assert result["returned_count"] == 1
    record = result["records"][0]
    assert record["path"] == "/22/abc"
    assert record["query_parameter_names"] == ["uid", "x"]
    assert "secret" not in str(result)
    assert "unrelated.example" not in str(result)


def test_result_accepts_subdomains_of_filter(monkeypatch) -> None:
    html = b'<a href="https://web.archive.org/web/*/https://cdn.example.org/a.js">x</a>'

    monkeypatch.setattr(
        public_scan_results,
        "public_get",
        lambda url, *, max_bytes: (url, 200, {}, html),
    )
    result = inspect_public_urlscan_result(
        "01a132ef-f666-7119-8739-4d9058646ff2", ["example.org"]
    )
    assert result["records"][0]["host"] == "cdn.example.org"
