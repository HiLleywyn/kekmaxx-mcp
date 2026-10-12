"""Read-only helpers for the FCC online public inspection file API."""

from __future__ import annotations

import argparse
import json
import re
from urllib.parse import quote

from .safety import public_get

FCC_MANAGER_BASE = "https://publicfiles.fcc.gov/api/manager"
ENTITY_ID_RE = re.compile(r"^[1-9][0-9]{0,11}$")
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _entity_id(value: int | str) -> str:
    entity = str(value).strip()
    if not ENTITY_ID_RE.fullmatch(entity):
        raise ValueError("FCC entity ID must be a positive numeric identifier")
    return entity


def _uuid(value: str, label: str) -> str:
    identifier = str(value).strip()
    if not UUID_RE.fullmatch(identifier):
        raise ValueError(f"{label} must be a UUID")
    return identifier.lower()


def _search_key(value: str) -> str:
    key = str(value).strip()
    if not key or len(key) > 200 or any(ord(character) < 32 for character in key):
        raise ValueError("Search key must contain 1 to 200 printable characters")
    return key


def _get_json(url: str, *, timeout: float = 60) -> dict | list:
    _, status, _, body = public_get(url, max_bytes=10_000_000, timeout=timeout)
    if status != 200:
        raise RuntimeError(f"FCC public-file API returned HTTP {status}")
    try:
        payload = json.loads(body.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("FCC public-file API returned invalid JSON") from exc
    if not isinstance(payload, (dict, list)):
        raise RuntimeError("FCC public-file API returned an unexpected response")
    return payload


def search_entity_files(
    entity_id: int | str, search_key: str, *, timeout: float = 60
) -> dict:
    """Search public-file metadata for one known FCC station/entity ID.

    This calls the FCC's fixed public search endpoint. It does not enumerate
    entities, folders, or identifiers and it does not download file contents.
    """
    entity = _entity_id(entity_id)
    key = _search_key(search_key)
    url = f"{FCC_MANAGER_BASE}/search/key/{quote(key, safe='')}.json?entityId={entity}"
    return {
        "entity_id": entity,
        "search_key": key,
        "source_url": url,
        "response": _get_json(url, timeout=timeout),
        "caveat": (
            "Search results establish public-file metadata and availability, not the "
            "contents or meaning of an underlying order, invoice, or disclosure."
        ),
    }


def get_file_details(
    entity_id: int | str, file_id: str, *, timeout: float = 60
) -> dict:
    """Retrieve FCC metadata for one already-known public file identifier."""
    entity = _entity_id(entity_id)
    identifier = _uuid(file_id, "FCC file ID")
    url = f"{FCC_MANAGER_BASE}/file/id/{identifier}.json?entityId={entity}"
    return {
        "entity_id": entity,
        "file_id": identifier,
        "source_url": url,
        "response": _get_json(url, timeout=timeout),
    }


def build_download_url(folder_id: str, file_manager_id: str) -> str:
    """Build the documented PDF URL from identifiers returned by FCC metadata."""
    folder = _uuid(folder_id, "FCC folder ID")
    manager = _uuid(file_manager_id, "FCC file-manager ID")
    return f"{FCC_MANAGER_BASE}/download/{folder}/{manager}.pdf"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    search = sub.add_parser("search", help="search file metadata for a known FCC entity")
    search.add_argument("--entity-id", required=True)
    search.add_argument("--search-key", required=True)
    details = sub.add_parser("details", help="retrieve metadata for a known FCC file ID")
    details.add_argument("--entity-id", required=True)
    details.add_argument("--file-id", required=True)
    download = sub.add_parser("download-url", help="construct a public-file PDF URL")
    download.add_argument("--folder-id", required=True)
    download.add_argument("--file-manager-id", required=True)
    args = parser.parse_args()
    if args.command == "search":
        result: object = search_entity_files(args.entity_id, args.search_key)
    elif args.command == "details":
        result = get_file_details(args.entity_id, args.file_id)
    else:
        result = {"download_url": build_download_url(args.folder_id, args.file_manager_id)}
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
