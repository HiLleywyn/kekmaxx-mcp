from __future__ import annotations

import os
import time

import pytest

from kekmaxx_mcp.analysis import coordination_detect


@pytest.mark.performance
def test_bounded_coordination_performance():
    from test_coordination import posts

    started = time.monotonic()
    coordination_detect(posts(), permutations=99)
    assert time.monotonic() - started < 10


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("KEKMAXX_INTEGRATION") != "1", reason="Explicit public-network opt-in"
)
def test_public_sources_and_browser_live():
    from kekmaxx_mcp.browser import browse
    from kekmaxx_mcp.sources import source_collect

    snapshot = source_collect("lobbying", "Synthetic unlikely organization", limit=1)
    assert snapshot["raw_sha256"] and snapshot["record_count"] <= 1
    page = browse("https://example.com/", wait_seconds=0)
    assert page["final_url"].startswith("https://example.com/")
