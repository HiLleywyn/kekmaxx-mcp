"""Explicit case-scoped watches, immutable versions and deduplicated local alerts."""

from __future__ import annotations

import json
import time
from difflib import unified_diff
from uuid import uuid4

from .models import canonical, digest, now
from .sources import source_collect

SCHEMA = """
CREATE TABLE IF NOT EXISTS watches(id TEXT PRIMARY KEY,case_id TEXT NOT NULL,
 request TEXT NOT NULL,interval INTEGER NOT NULL,next_due REAL NOT NULL,failures INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS versions(seq INTEGER PRIMARY KEY AUTOINCREMENT,
 id TEXT UNIQUE NOT NULL,watch_id TEXT NOT NULL,
 evidence_id TEXT NOT NULL,sha256 TEXT NOT NULL,created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY,watch_id TEXT NOT NULL,
 old_version TEXT NOT NULL,new_version TEXT NOT NULL,data TEXT NOT NULL,created TEXT NOT NULL,
 UNIQUE(watch_id,old_version,new_version));
"""


def monitor_configure(store, case_id, request, interval_seconds=3600):
    store.require_case(case_id)
    if not 300 <= interval_seconds <= 2_592_000:
        raise ValueError("Monitoring interval must be 5 minutes to 30 days")
    from .sources import endpoint

    endpoint(**request)  # Validate the scope before persisting, without collecting.
    store.db.executescript(SCHEMA)
    watch = str(uuid4())
    with store.db:
        store.db.execute(
            "INSERT INTO watches(id,case_id,request,interval,next_due) VALUES(?,?,?,?,?)",
            (watch, case_id, canonical(request), interval_seconds, 0),
        )
        store.audit(case_id, "watch_create", {"id": watch, "request": request})
    return {
        "watch_id": watch,
        "interval_seconds": interval_seconds,
        "execution": "Run monitor_run or the CLI monitor worker; no scheduler installed silently.",
    }


def monitor_run(store, case_id, *, limit=10):
    store.require_case(case_id)
    store.db.executescript(SCHEMA)
    if not 1 <= limit <= 20:
        raise ValueError("Monitor batch limit is 1 to 20")
    results = []
    # Claim each due watch transactionally across CLI/MCP processes.
    watches = store.db.execute(
        "SELECT id FROM watches WHERE case_id=? AND next_due<=? ORDER BY next_due,id LIMIT ?",
        (case_id, time.time(), limit),
    ).fetchall()
    for candidate in watches:
        with store.db:
            watch = store.db.execute(
                "UPDATE watches SET next_due=? WHERE id=? AND next_due<=? RETURNING *",
                (time.time() + 600, candidate["id"], time.time()),
            ).fetchone()
        if watch is None:
            continue
        try:
            snapshot = source_collect(**json.loads(watch["request"]))
            # Ignore retrieval time/order for a stable semantic comparison.
            content = canonical(sorted(snapshot["records"], key=canonical))
            hashed = digest(content)
            previous = store.db.execute(
                "SELECT * FROM versions WHERE watch_id=? ORDER BY seq DESC LIMIT 1",
                (watch["id"],),
            ).fetchone()
            changed = previous is None or previous["sha256"] != hashed
            if changed:
                evidence = store.add(
                    case_id,
                    "evidence",
                    {
                        "source_url": snapshot["source_url"],
                        "source_type": snapshot["source"],
                        "content": content,
                        "retrieved_at": snapshot["retrieved_at"],
                        "artifact_sha256": snapshot["raw_sha256"],
                        "extraction_method": "source-normalizer",
                        "limitations": snapshot["limitations"]
                        + [f"Coverage complete: {snapshot['coverage_complete']}"],
                        "supersedes": previous["evidence_id"] if previous else None,
                    },
                )
                version = str(uuid4())
                with store.db:
                    store.db.execute(
                        "INSERT INTO versions(id,watch_id,evidence_id,sha256,created) "
                        "VALUES(?,?,?,?,?)",
                        (version, watch["id"], evidence["id"], hashed, now()),
                    )
                    if previous:
                        old = store.get(case_id, previous["evidence_id"], "evidence")["data"][
                            "content"
                        ]
                        delta = "\n".join(
                            unified_diff(
                                old.splitlines(),
                                content.splitlines(),
                                fromfile="previous",
                                tofile="current",
                            )
                        )[:10_000]
                        alert = {
                            "old_evidence_id": previous["evidence_id"],
                            "new_evidence_id": evidence["id"],
                            "change_excerpt": delta,
                            "observation": "Published source records changed.",
                            "limitations": [
                                "Removal may reflect amendments, outages or coverage gaps."
                            ],
                        }
                        store.db.execute(
                            "INSERT OR IGNORE INTO alerts VALUES(?,?,?,?,?,?)",
                            (
                                str(uuid4()),
                                watch["id"],
                                previous["id"],
                                version,
                                canonical(alert),
                                now(),
                            ),
                        )
                    store.audit(
                        case_id,
                        "watch_change",
                        {"watch_id": watch["id"], "evidence_id": evidence["id"]},
                    )
            with store.db:
                store.db.execute(
                    "UPDATE watches SET failures=0,next_due=? WHERE id=?",
                    (time.time() + watch["interval"], watch["id"]),
                )
            results.append({"watch_id": watch["id"], "changed": changed, "ok": True})
        except Exception:
            with store.db:
                store.db.execute(
                    "UPDATE watches SET failures=failures+1,next_due=? WHERE id=?",
                    (time.time() + min(86400, 300 * 2 ** min(watch["failures"], 8)), watch["id"]),
                )
                store.audit(
                    case_id,
                    "watch_failure",
                    {"watch_id": watch["id"], "error": "Collection failed; retry scheduled"},
                )
            results.append({"watch_id": watch["id"], "ok": False, "error": "Collection failed"})
    return {
        "results": results,
        "alerts": [
            json.loads(r[0])
            for r in store.db.execute(
                "SELECT a.data FROM alerts a JOIN watches w ON w.id=a.watch_id WHERE w.case_id=? "
                "ORDER BY a.created DESC LIMIT 100",
                (case_id,),
            )
        ],
    }
