from __future__ import annotations

import json

import pytest

from kekmaxxing_mcp import fcc


def test_search_uses_fixed_fcc_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def fake_get(url: str, **_: object) -> tuple[str, int, dict, bytes]:
        seen.append(url)
        return url, 200, {}, json.dumps({"files": [{"file_name": "Example"}]}).encode()

    monkeypatch.setattr(fcc, "public_get", fake_get)
    result = fcc.search_entity_files("12345", "Example Committee")
    assert seen == [
        "https://publicfiles.fcc.gov/api/manager/search/key/"
        "Example%20Committee.json?entityId=12345"
    ]
    assert result["response"]["files"][0]["file_name"] == "Example"
    assert "contents" in result["caveat"]


def test_file_details_requires_uuid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        fcc,
        "public_get",
        lambda url, **_: (url, 200, {}, b'{"id":"ok"}'),
    )
    identifier = "11111111-1111-1111-1111-111111111111"
    result = fcc.get_file_details(12345, identifier)
    assert result["file_id"] == identifier.lower()
    with pytest.raises(ValueError, match="UUID"):
        fcc.get_file_details(12345, "../../private")


def test_download_url_accepts_only_uuid_identifiers() -> None:
    result = fcc.build_download_url(
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
    )
    assert result.endswith(
        "/11111111-1111-1111-1111-111111111111/"
        "22222222-2222-2222-2222-222222222222.pdf"
    )
    with pytest.raises(ValueError):
        fcc.build_download_url("not-a-uuid", "22222222-2222-2222-2222-222222222222")


@pytest.mark.parametrize("entity", ["", "0", "-1", "12?other=1", "abc"])
def test_rejects_invalid_entity_ids(entity: str) -> None:
    with pytest.raises(ValueError):
        fcc.search_entity_files(entity, "Example")


@pytest.mark.parametrize("key", ["", "\n", "x" * 201])
def test_rejects_invalid_search_keys(key: str) -> None:
    with pytest.raises(ValueError):
        fcc.search_entity_files("12345", key)
