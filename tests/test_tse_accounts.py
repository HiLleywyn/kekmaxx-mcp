from __future__ import annotations

import csv
import io
import zipfile
from pathlib import Path

from kekmaxxing_mcp.tse_accounts import (
    compare_tse_candidate_accounts,
    inspect_tse_candidate_accounts,
)

FIELDS = [
    "DT_GERACAO",
    "DT_PRESTACAO_CONTAS",
    "NR_CNPJ_PRESTADOR_CONTA",
    "NM_CANDIDATO",
    "DS_TIPO_FORNECEDOR",
    "NR_CPF_CNPJ_FORNECEDOR",
    "NM_FORNECEDOR",
    "NM_FORNECEDOR_RFB",
    "DS_ORIGEM_DESPESA",
    "SQ_DESPESA",
    "DT_DESPESA",
    "DS_DESPESA",
    "VR_DESPESA_CONTRATADA",
]


def _archive(path: Path, rows: list[dict[str, str]]) -> None:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=FIELDS, delimiter=";", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(
            "despesas_contratadas_candidatos_2026_BR.csv",
            stream.getvalue().encode("latin-1"),
        )


def _row(**updates: str) -> dict[str, str]:
    row = {
        "DT_GERACAO": "11/10/2026",
        "DT_PRESTACAO_CONTAS": "09/10/2026",
        "NR_CNPJ_PRESTADOR_CONTA": "68475818000102",
        "NM_CANDIDATO": "CANDIDATO TESTE",
        "DS_TIPO_FORNECEDOR": "PESSOA JURÍDICA",
        "NR_CPF_CNPJ_FORNECEDOR": "12345678000199",
        "NM_FORNECEDOR": "AGÊNCIA EXEMPLO LTDA",
        "NM_FORNECEDOR_RFB": "AGENCIA EXEMPLO LTDA",
        "DS_ORIGEM_DESPESA": "Serviços prestados por terceiros",
        "SQ_DESPESA": "100",
        "DT_DESPESA": "08/10/2026",
        "DS_DESPESA": "Comunicação digital",
        "VR_DESPESA_CONTRATADA": "1200,50",
    }
    row.update(updates)
    return row


def test_inspect_tse_archive_summarizes_and_redacts_person_identifier(tmp_path: Path) -> None:
    archive = tmp_path / "accounts.zip"
    _archive(
        archive,
        [
            _row(),
            _row(
                SQ_DESPESA="101",
                DS_TIPO_FORNECEDOR="PESSOA FÍSICA",
                NR_CPF_CNPJ_FORNECEDOR="12345678901",
                NM_FORNECEDOR="PROFISSIONAL PÚBLICO",
                VR_DESPESA_CONTRATADA="300,00",
            ),
            _row(NR_CNPJ_PRESTADOR_CONTA="00000000000000", SQ_DESPESA="999"),
        ],
    )

    result = inspect_tse_candidate_accounts(
        archive, "68.475.818/0001-02", ["agencia", "comunicação", "profissional"]
    )

    assert result["contracted_row_count"] == 2
    assert result["contracted_total_brl"] == "1500.50"
    assert result["term_match_counts"] == {
        "agencia": 2,
        "comunicação": 2,
        "profissional": 1,
    }
    assert result["matches"][0]["supplier_cnpj"] == "12345678000199"
    assert result["matches"][1]["supplier_cnpj"] is None
    assert "12345678901" not in str(result)


def test_compare_tse_archives_reports_added_matching_transaction(tmp_path: Path) -> None:
    previous = tmp_path / "previous.zip"
    current = tmp_path / "current.zip"
    _archive(previous, [_row()])
    _archive(current, [_row(), _row(SQ_DESPESA="102", VR_DESPESA_CONTRATADA="200,00")])

    result = compare_tse_candidate_accounts(previous, current, "68475818000102", ["digital"])

    assert result["delta"]["contracted_row_count"] == 1
    assert result["delta"]["contracted_total_brl"] == "200.00"
    assert result["delta"]["added_transaction_count"] == 1
    assert len(result["delta"]["added_matching_transactions"]) == 1
