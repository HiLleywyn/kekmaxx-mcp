from __future__ import annotations

from kekmaxx_mcp.passive import _jaccard


def test_jaccard() -> None:
    assert _jaccard({"a", "b"}, {"b", "c"}) == 1 / 3
    assert _jaccard(set(), set()) == 1.0
