---
name: political-money
description: Reconcile disclosed campaign transactions, amendments and shared vendors while separating different financial measures.
---

Inputs: case_id and `financial_records` with source, transaction_id, documented
revision, measure, amount, currency, evidence_id, payer_id and payee_id.
Collect using existing FEC, FCC, procurement, Google advertising or TSE tools.
Preserve original source output with `investigation_add_evidence`; normalized
records retain those references. Do not invent amendment lineage.

Run `investigation_workflow_run` profile `political-money` with financial_records.
Inspect superseded transactions and totals by measure/currency. Review shared
vendors as service relationships; add supported typed graph edges separately.

Expected outputs: reproducible current transactions, separate totals, vendor
relationships and source-linked report. Conflicting same-revision records fail
closed for investigator review. Reported expenditures, delivery, invoices,
obligations and payments are different measures. Verify integrity and source
lineage; unrelated clients sharing a vendor are a required negative control.
