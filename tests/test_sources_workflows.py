from __future__ import annotations

import json
import time

import pytest

from kekmaxxing_mcp import monitoring, reasoning, sources, workflows
from kekmaxxing_mcp.store import CaseStore


def test_source_normalizers_strip_personal_contacts_and_preserve_ids():
    payload = {
        "results": [
            {
                "filing_uuid": "synthetic",
                "registrant": {
                    "id": 1,
                    "name": "Example LLC",
                    "contact_telephone": "redact",
                    "address_1": "redact",
                },
                "client": {"id": 2, "name": "Another LLC"},
            }
        ],
        "next": None,
    }
    rows, complete = sources.normalize("lobbying", json.dumps(payload).encode(), "Example", 50)
    assert rows[0]["registrant"] == {"id": 1, "name": "Example LLC"}
    assert complete
    fara, _ = sources.normalize(
        "fara",
        json.dumps([{"Registrant_Name": "Example", "Registration_Number": 1}]).encode(),
        "Example",
        50,
    )
    assert fara[0]["Registration_Number"] == 1


def test_rss_atom_edgar_irs_archive_and_missing_schema():
    assert (
        sources.normalize(
            "rss",
            b"<rss><channel><item><title>Public</title>"
            b"<link>https://example.org/</link></item></channel></rss>",
            "",
            1,
        )[0][0]["title"]
        == "Public"
    )
    assert sources.normalize(
        "rss",
        b'<feed xmlns="http://www.w3.org/2005/Atom"><entry>'
        b'<title>Public</title><link href="https://example.org/"/></entry></feed>',
        "",
        1,
    )[0][0]["link"]
    edgar = {
        "cik": "1",
        "name": "Example",
        "filings": {
            "recent": {
                "accessionNumber": ["example"],
                "form": ["10-K"],
                "filingDate": ["2026-01-01"],
            }
        },
    }
    assert (
        sources.normalize("edgar", json.dumps(edgar).encode(), "1", 10)[0][0]["filings"][0]["form"]
        == "10-K"
    )
    irs, _ = sources.normalize(
        "irs990", b"<Return><EIN>000000000</EIN><PhoneNum>omit</PhoneNum></Return>", "", 50
    )
    assert irs == [{"EIN": "000000000"}]
    assert (
        sources.normalize(
            "archive", b'[["timestamp","original"],["20260101","https://example.org/"]]', "", 50
        )[0][0]["timestamp"]
        == "20260101"
    )
    with pytest.raises(ValueError):
        sources.normalize("fara", b'{"unexpected":true}', "Example", 50)


def test_connector_budgets_external_requirements_and_partial_failures(monkeypatch):
    with pytest.raises(ValueError):
        sources.endpoint("meta_ads", "Example")
    with pytest.raises(ValueError):
        sources.endpoint("rss", "file:///private")
    with pytest.raises(ValueError):
        sources.endpoint("commoncrawl", "https://example.org/", collection="../")
    monkeypatch.setattr(
        sources,
        "source_collect",
        lambda **kw: (_ for _ in ()).throw(RuntimeError("Unavailable public endpoint")),
    )
    result = sources.cross_source_search([{"source": "rss", "query": "https://example.org/"}])
    assert not result["complete"] and not result["results"][0]["ok"]


def test_money_amendments_unrelated_vendor_clients_and_conflicts():
    def row(transaction, revision, amount, payer="one", measure="reported_expenditure"):
        return dict(
            source="official",
            transaction_id=transaction,
            revision=revision,
            amount=amount,
            payer_id=payer,
            payee_id="vendor",
            evidence_id="source",
            currency="USD",
            measure=measure,
        )

    result = reasoning.political_finance_trace(
        [
            row("A", 1, "10"),
            row("A", 2, "20"),
            row("B", 1, "30", "two"),
            row("C", 1, "40", measure="payment"),
        ]
    )
    assert result["superseded_or_duplicate_count"] == 1
    assert result["totals"] == [
        {"measure": "payment", "currency": "USD", "amount": "40"},
        {"measure": "reported_expenditure", "currency": "USD", "amount": "50"},
    ]
    assert len(result["shared_vendors"]) == 1
    with pytest.raises(ValueError):
        reasoning.political_finance_trace([row("A", 1, "10"), row("A", 1, "20")])


def test_monitor_versions_dedup_missing_records_and_failure_recovery(tmp_path, monkeypatch):
    # Windows clocks can assign identical timestamps to successive revisions.
    monkeypatch.setattr(monitoring, "now", lambda: "2026-01-01T00:00:00Z")
    snapshot = {
        "source_url": "https://example.org/feed",
        "source": "rss",
        "retrieved_at": "2026-01-01T00:00:00Z",
        "raw_sha256": "0" * 64,
        "records": [{"title": "Original"}],
        "coverage_complete": True,
        "limitations": [],
    }
    monkeypatch.setattr(monitoring, "source_collect", lambda **kwargs: snapshot)
    with CaseStore(tmp_path / "test.db") as store:
        cid = store.create("Monitoring")["id"]
        watch = monitoring.monitor_configure(
            store, cid, {"source": "rss", "query": "https://example.org/feed"}
        )

        def due():
            store.db.execute("UPDATE watches SET next_due=0")
            store.db.commit()

        assert monitoring.monitor_run(store, cid)["results"][0]["changed"]
        due()
        assert not monitoring.monitor_run(store, cid)["results"][0]["changed"]
        snapshot["records"] = [{"title": "Amended"}]
        due()
        result = monitoring.monitor_run(store, cid)
        assert len(result["alerts"]) == 1
        assert "Amended" in result["alerts"][0]["change_excerpt"]
        due()
        assert len(monitoring.monitor_run(store, cid)["alerts"]) == 1
        monkeypatch.setattr(
            monitoring, "source_collect", lambda **kw: (_ for _ in ()).throw(RuntimeError())
        )
        due()
        assert not monitoring.monitor_run(store, cid)["results"][0]["ok"]
        assert (
            store.db.execute(
                "SELECT next_due FROM watches WHERE id=?", (watch["watch_id"],)
            ).fetchone()[0]
            > time.time()
        )
        assert len(store.all_records(cid, "evidence")) == 2
        assert store.integrity(cid)["valid"]


def test_all_ten_workflows_execute_on_attributed_synthetic_case(tmp_path, monkeypatch):
    from test_coordination import posts

    monkeypatch.setattr(
        workflows, "cross_source_search", lambda requests: {"results": [], "complete": False}
    )
    with CaseStore(tmp_path / "test.db") as store:
        cid = store.create("End-to-end synthetic investigation")["id"]
        evidence = store.add(
            cid,
            "evidence",
            {
                "source_url": "https://example.org/record",
                "source_type": "official_record",
                "content": "Synthetic organizational disclosure.",
            },
        )["id"]
        inputs = {
            "posts": posts(),
            "sources": [{"source": "rss", "query": "https://example.org/feed"}],
            "financial_records": [
                {
                    "source": "official",
                    "transaction_id": "A",
                    "revision": 1,
                    "amount": "5",
                    "currency": "USD",
                    "payer_id": "one",
                    "payee_id": "vendor",
                    "measure": "reported_expenditure",
                    "evidence_id": evidence,
                }
            ],
            "evidence_ids": [evidence],
            "classification_evidence_ids": [evidence],
            "official_evidence_ids": [evidence],
            "infrastructure_evidence_ids": [evidence],
        }
        for profile in workflows.PROFILES:
            result = workflows.workflow_run(store, cid, profile, inputs)
            assert result["outputs"]
        assert len(workflows.PROFILES) == 10
