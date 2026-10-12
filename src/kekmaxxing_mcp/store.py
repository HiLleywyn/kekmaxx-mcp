"""SQLite/FTS5 case storage. Records and audit history are append-only."""

from __future__ import annotations

import json
import os
import sqlite3
import unicodedata
from difflib import SequenceMatcher
from pathlib import Path
from uuid import uuid4

from .models import RECORD_MODELS, canonical, digest, now, redact

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY, title TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS records(
 seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
 case_id TEXT NOT NULL REFERENCES cases(id), kind TEXT NOT NULL,
 data TEXT NOT NULL, sha256 TEXT NOT NULL, created TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS record_case_kind ON records(case_id,kind,seq);
CREATE VIRTUAL TABLE IF NOT EXISTS search
 USING fts5(id UNINDEXED,case_id UNINDEXED,kind UNINDEXED,text);
CREATE TABLE IF NOT EXISTS audit(
 seq INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, action TEXT NOT NULL,
 data TEXT NOT NULL, created TEXT NOT NULL, previous TEXT NOT NULL, sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS merges(
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL, source TEXT NOT NULL, target TEXT NOT NULL,
 evidence_ids TEXT NOT NULL, reason TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS undo_merges(
 id TEXT PRIMARY KEY REFERENCES merges(id), created TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS immutable_record_update BEFORE UPDATE ON records
 BEGIN SELECT RAISE(ABORT,'records are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_record_delete BEFORE DELETE ON records
 BEGIN SELECT RAISE(ABORT,'records are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_audit_update BEFORE UPDATE ON audit
 BEGIN SELECT RAISE(ABORT,'audit is immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_audit_delete BEFORE DELETE ON audit
 BEGIN SELECT RAISE(ABORT,'audit is immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_merge_update BEFORE UPDATE ON merges
 BEGIN SELECT RAISE(ABORT,'merges are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_merge_delete BEFORE DELETE ON merges
 BEGIN SELECT RAISE(ABORT,'merges are immutable'); END;
"""


def fold(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


class CaseStore:
    def __init__(self, path: str | Path | None = None):
        root = Path(
            os.environ.get("KEKMAXX_DATA_DIR", str(Path.home() / ".local/share/kekmaxxing-mcp"))
        ).expanduser()
        self.path = Path(path) if path else root / "cases.sqlite3"
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(self.path, timeout=15)
        if os.name != "nt":
            self.path.chmod(0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def audit(self, case_id, action, data):
        previous = self.db.execute("SELECT sha256 FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prior = previous[0] if previous else ""
        stamp, payload = now(), canonical(data)
        hashed = digest(canonical([case_id, action, payload, stamp, prior]))
        self.db.execute(
            "INSERT INTO audit(case_id,action,data,created,previous,sha256) VALUES(?,?,?,?,?,?)",
            (case_id, action, payload, stamp, prior, hashed),
        )

    def require_case(self, case_id):
        row = self.db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            raise ValueError("Unknown investigation")
        return dict(row)

    def create(self, title: str) -> dict:
        if not 1 <= len(title.strip()) <= 200:
            raise ValueError("Title must contain 1 to 200 characters")
        case = {"id": str(uuid4()), "title": redact(title.strip()), "created": now()}
        with self.db:
            self.db.execute("INSERT INTO cases VALUES(:id,:title,:created)", case)
            self.audit(case["id"], "create", case)
        return case

    def get(self, case_id, record_id, kind=None):
        row = self.db.execute(
            "SELECT * FROM records WHERE case_id=? AND id=?", (case_id, record_id)
        ).fetchone()
        if not row or (kind and row["kind"] != kind):
            raise ValueError("Unknown record or wrong record type in this investigation")
        result = dict(row)
        result["data"] = json.loads(row["data"])
        return result

    def evidence_refs(self, case_id, refs):
        for ref in refs:
            self.get(case_id, ref, "evidence")

    def add(self, case_id: str, kind: str, data: dict) -> dict:
        self.require_case(case_id)
        if kind not in RECORD_MODELS:
            raise ValueError("Unsupported investigation record type")
        data = RECORD_MODELS[kind].model_validate(data).model_dump(mode="json")
        self.evidence_refs(case_id, data.get("evidence_ids", []))
        self.evidence_refs(case_id, data.get("contradicting_evidence_ids", []))
        if kind == "relationship":
            self.get(case_id, data["source"], "entity")
            self.get(case_id, data["target"], "entity")
        if kind == "evidence":
            # Hash the exact submitted excerpt separately from its privacy-minimized copy.
            data["content_sha256"] = digest(data["content"])
            data["content"] = redact(data["content"])
            data["stored_content_sha256"] = digest(data["content"])
            if data["supersedes"]:
                self.get(case_id, data["supersedes"], "evidence")
        payload = canonical(data)
        if len(payload.encode()) > 1_000_000:
            raise ValueError("Record exceeded storage budget")
        record_id = str(uuid4())
        with self.db:
            self.db.execute(
                "INSERT INTO records(id,case_id,kind,data,sha256,created) VALUES(?,?,?,?,?,?)",
                (record_id, case_id, kind, payload, digest(payload), now()),
            )
            self.db.execute(
                "INSERT INTO search VALUES(?,?,?,?)", (record_id, case_id, kind, payload)
            )
            self.audit(case_id, "add", {"id": record_id, "kind": kind, "sha256": digest(payload)})
        return self.get(case_id, record_id)

    def records(self, case_id, kind=None, *, after=0, limit=100):
        self.require_case(case_id)
        if not 1 <= limit <= 1000 or after < 0:
            raise ValueError("Pagination limit is 1 to 1000; cursor is nonnegative")
        rows = self.db.execute(
            "SELECT id FROM records WHERE case_id=? AND seq>? "
            "AND (? IS NULL OR kind=?) ORDER BY seq LIMIT ?",
            (case_id, after, kind, kind, limit),
        ).fetchall()
        return [self.get(case_id, row["id"]) for row in rows]

    def all_records(self, case_id, kind=None):
        records, after = [], 0
        while page := self.records(case_id, kind, after=after, limit=1000):
            records.extend(page)
            after = page[-1]["seq"]
            if len(records) > 50_000:
                raise ValueError("Case exceeds 50,000-record analysis/export budget")
        return records

    def search(self, case_id, query, *, after=0, limit=100):
        self.require_case(case_id)
        if not query.strip() or len(query) > 500 or not 1 <= limit <= 1000:
            raise ValueError("Invalid search query or pagination budget")
        # Literal token conjunction, not an untrusted FTS expression.
        expression = " AND ".join('"' + x.replace('"', '""') + '"' for x in query.split())
        rows = self.db.execute(
            "SELECT r.id FROM search s JOIN records r ON r.id=s.id "
            "WHERE search MATCH ? AND s.case_id=? AND r.seq>? ORDER BY r.seq LIMIT ?",
            (expression, case_id, after, limit),
        ).fetchall()
        return [self.get(case_id, r[0]) for r in rows]

    def aliases(self, case_id):
        merges = self.db.execute(
            "SELECT * FROM merges WHERE case_id=? AND id NOT IN "
            "(SELECT id FROM undo_merges) ORDER BY created,id",
            (case_id,),
        ).fetchall()
        return {m["source"]: m["target"] for m in merges}

    def resolve_id(self, case_id, entity_id):
        aliases, seen = self.aliases(case_id), set()
        while entity_id in aliases:
            if entity_id in seen:
                raise ValueError("Entity merge cycle")
            seen.add(entity_id)
            entity_id = aliases[entity_id]
        return entity_id

    def merge(self, case_id, source, target, evidence_ids, reason):
        self.get(case_id, source, "entity")
        self.get(case_id, target, "entity")
        if not evidence_ids or not reason.strip():
            raise ValueError("Explicit merges require evidence and a reason")
        self.evidence_refs(case_id, evidence_ids)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if source in self.aliases(case_id) or self.resolve_id(case_id, target) == source:
                raise ValueError("Merge would replace an active decision or create a cycle")
            decision = str(uuid4())
            self.db.execute(
                "INSERT INTO merges VALUES(?,?,?,?,?,?,?)",
                (decision, case_id, source, target, canonical(evidence_ids), reason, now()),
            )
            self.audit(
                case_id,
                "merge",
                {
                    "decision": decision,
                    "source": source,
                    "target": target,
                    "evidence_ids": evidence_ids,
                    "reason": reason,
                },
            )
        return {"decision_id": decision, "source": source, "target": target}

    def undo_merge(self, case_id, decision):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT id FROM merges WHERE case_id=? AND id=?", (case_id, decision)
            ).fetchone()
            if not row:
                raise ValueError("Unknown merge decision")
            self.db.execute("INSERT OR IGNORE INTO undo_merges VALUES(?,?)", (decision, now()))
            self.audit(case_id, "undo_merge", {"decision": decision})
        return {"reversed": decision}

    def candidates(self, case_id, entity: dict):
        incoming = RECORD_MODELS["entity"].model_validate(entity)
        matches = []
        for row in self.all_records(case_id, "entity"):
            existing = row["data"]
            exact = sorted(
                k
                for k, v in incoming.identifiers.items()
                if v and existing["identifiers"].get(k) == v
            )
            conflict = sorted(
                k
                for k, v in incoming.identifiers.items()
                if existing["identifiers"].get(k) not in (None, v)
            )
            similarity = max(
                SequenceMatcher(None, fold(incoming.name), fold(x)).ratio()
                for x in [existing["name"], *existing["aliases"]]
            )
            if exact or similarity >= 0.6:
                matches.append(
                    {
                        "entity_id": row["id"],
                        "exact_identifiers": exact,
                        "conflicting_identifiers": conflict,
                        "name_similarity": round(similarity, 4),
                        "candidate_score": 1
                        if exact and not conflict
                        else round(similarity * 0.5, 4),
                        "requires_review": True,
                    }
                )
        return sorted(matches, key=lambda r: (-r["candidate_score"], r["entity_id"]))[:100]

    def integrity(self, case_id):
        errors = []
        for row in self.all_records(case_id):
            if digest(canonical(row["data"])) != row["sha256"]:
                errors.append({"record": row["id"], "error": "record hash mismatch"})
            if row["kind"] == "evidence":
                if digest(row["data"]["content"]) != row["data"]["stored_content_sha256"]:
                    errors.append({"record": row["id"], "error": "stored excerpt hash mismatch"})
        previous = ""
        for row in self.db.execute("SELECT * FROM audit ORDER BY seq"):
            expected = digest(
                canonical([row["case_id"], row["action"], row["data"], row["created"], previous])
            )
            if row["previous"] != previous or row["sha256"] != expected:
                errors.append({"audit_seq": row["seq"], "error": "audit chain mismatch"})
            payload = json.loads(row["data"])
            if row["action"] == "add" and row["case_id"] == case_id:
                current = self.get(case_id, payload["id"])
                if current["sha256"] != payload["sha256"]:
                    errors.append({"record": payload["id"], "error": "record differs from audit"})
            if row["action"] == "merge" and row["case_id"] == case_id:
                decision = self.db.execute(
                    "SELECT * FROM merges WHERE id=?", (payload["decision"],)
                ).fetchone()
                if (
                    not decision
                    or any(decision[k] != payload[k] for k in ["source", "target", "reason"])
                    or json.loads(decision["evidence_ids"]) != payload["evidence_ids"]
                ):
                    errors.append(
                        {"decision": payload["decision"], "error": "merge differs from audit"}
                    )
            previous = row["sha256"]
        return {
            "valid": not errors,
            "errors": errors,
            "audit_head": previous,
            "limitations": ["Hashes detect changes, not source truth or external authenticity."],
        }
