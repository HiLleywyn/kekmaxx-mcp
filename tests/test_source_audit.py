from __future__ import annotations

import subprocess
from pathlib import Path

from kekmaxxing_mcp.source_audit import (
    SourceAuditError,
    analyze_complexity_series,
    analyze_paired_benchmark_trials,
    source_cache_key_hotspots,
    source_complexity_hotspots,
    source_lifetime_hotspots,
    source_parser_progress_hotspots,
    source_snapshot_manifest,
    source_validation_hotspots,
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        shell=False,
    )


def _repository(tmp_path: Path) -> Path:
    repo = tmp_path / "example-source"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test Fixture")
    (repo / "worker.c").write_text(
        """\
void cleanup(struct event *event) {
    destroy_pool(event->data->pool);
}

void queue(struct request *request) {
    request->event.handler = cleanup;
    add_timer(&request->event, 10);
}

int compile_pattern(char *data, int len) {
    for (int i = 0; i < len; i++) {
        for (int j = i; j < len; j++) {
            if (ngx_memcmp(data, data + i, j) == 0) return j;
        }
    }
    return 0;
}

int validate_response(void *response, void *chain) {
    if (OCSP_basic_verify(response, chain, NULL, OCSP_NOVERIFY) != 1) return 0;
    return 1;
}

int parse_records(struct packet *packet, struct header *header) {
    for (int i = 0; i < header->record_count; i++) {
        int length = read_record(packet->reader, &packet->offset);
        if (length == 0) continue;
        packet->reader += packet->offset;
    }
    return 1;
}

void build_cache_key(struct buffer *key, struct request *request) {
    cache_hash_add(key, "https://");
    cache_hash_add(key, request->host);
    cache_hash_add(key, request->uri);
}

int retry_interrupted_read(int fd, char *buffer, int size) {
    int position = 0;
    while (position < size) {
        int length = read(fd, buffer + position, size - position);
        if (length < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
        position += length;
    }
    return 1;
}
""",
        encoding="utf-8",
    )
    _git(repo, "add", "worker.c")
    _git(repo, "commit", "-m", "fixture")
    _git(repo, "remote", "add", "origin", "https://secret@example.test/org/project.git?token=x")
    return repo


def test_snapshot_is_deterministic_and_redacts_machine_paths(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    first = source_snapshot_manifest(str(repo))
    second = source_snapshot_manifest(str(repo))

    assert first["revision"] == second["revision"]
    assert first["index_sha256"] == second["index_sha256"]
    assert first["repository_name"] == "example-source"
    assert first["origin"] == {"host": "example.test", "repository": "/org/project.git"}
    assert str(tmp_path) not in repr(first)
    assert "secret" not in repr(first)
    assert first["network_access"] is False
    assert first["target_code_executed"] is False


def test_snapshot_reports_dirty_counts_without_file_names(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    (repo / "worker.c").write_text("changed\n", encoding="utf-8")
    (repo / "private-name.txt").write_text("untracked\n", encoding="utf-8")

    result = source_snapshot_manifest(str(repo))

    assert result["dirty"] is True
    assert result["change_counts"]["unstaged"] >= 1
    assert result["change_counts"]["untracked"] == 1
    assert "private-name.txt" not in repr(result)


def test_lifetime_hotspots_return_relative_bounded_leads(tmp_path: Path) -> None:
    repo = _repository(tmp_path)

    result = source_lifetime_hotspots(str(repo), max_results=5)

    assert result["matches"]
    assert result["matches"][0]["path"] == "worker.c"
    assert "async_schedule_or_callback" in result["matches"][0]["reason_tags"]
    assert str(repo) not in repr(result)
    assert len(result["matches"]) <= 5


def test_complexity_hotspots_find_nested_expensive_operation(tmp_path: Path) -> None:
    repo = _repository(tmp_path)

    result = source_complexity_hotspots(str(repo), max_results=5)

    match = next(item for item in result["matches"] if "memcmp" in item["excerpt"])
    assert match["path"] == "worker.c"
    assert "nested_loop_window" in match["reason_tags"]
    assert result["target_code_executed"] is False


def test_validation_hotspots_flag_relaxed_verifier_policy(tmp_path: Path) -> None:
    repo = _repository(tmp_path)

    result = source_validation_hotspots(str(repo), max_results=5)

    match = next(item for item in result["matches"] if "OCSP_basic_verify" in item["excerpt"])
    assert match["path"] == "worker.c"
    assert "verification_relaxation_flag_nearby" in match["reason_tags"]
    assert "null_validation_context_nearby" in match["reason_tags"]
    assert "result_predicate_requires_contract_review" in match["reason_tags"]
    assert str(repo) not in repr(result)
    assert result["network_access"] is False
    assert result["target_code_executed"] is False


def test_parser_progress_hotspots_flag_no_progress_continue(tmp_path: Path) -> None:
    repo = _repository(tmp_path)

    result = source_parser_progress_hotspots(str(repo), max_results=5)

    match = next(item for item in result["matches"] if "read_record" in item["excerpt"])
    assert match["path"] == "worker.c"
    assert "count_bounded_parser_loop" in match["reason_tags"]
    assert "parse_failure_continue_path" in match["reason_tags"]
    assert "no_cursor_progress_visible_before_continue" in match["reason_tags"]
    assert len(result["matches"]) == 1
    assert result["network_access"] is False
    assert result["target_code_executed"] is False


def test_cache_key_hotspots_flag_fixed_scheme_identity(tmp_path: Path) -> None:
    repo = _repository(tmp_path)

    result = source_cache_key_hotspots(str(repo), max_results=5)

    match = next(item for item in result["matches"] if '"https://"' in item["excerpt"])
    assert match["path"] == "worker.c"
    assert "fixed_scheme_literal_in_key_window" in match["reason_tags"]
    assert {"host", "uri"}.issubset(match["visible_dimensions"])
    assert result["network_access"] is False
    assert result["target_code_executed"] is False


def test_complexity_series_classifies_cubic_measurements_with_repeats() -> None:
    observations = [
        {"series": "repeated", "size": size, "cost": scale * size**3}
        for size in (64, 128, 256, 512)
        for scale in (0.95, 1.0, 1.05)
    ]

    result = analyze_complexity_series(observations)

    series = result["series"][0]
    assert series["classification"] == "approximately_cubic"
    assert series["log_log_exponent"] == 3.0
    assert series["r_squared"] == 1.0
    assert all(point["sample_count"] == 3 for point in series["points"])
    assert result["network_access"] is False
    assert result["target_code_executed"] is False


def test_complexity_series_keeps_controls_separate() -> None:
    observations = [
        {"series": series, "size": size, "cost": size**exponent}
        for series, exponent in (("control", 1), ("candidate", 2))
        for size in (32, 64, 128)
    ]

    result = analyze_complexity_series(observations)

    labels = {item["series"]: item["classification"] for item in result["series"]}
    assert labels == {
        "candidate": "approximately_quadratic",
        "control": "approximately_linear",
    }


def test_complexity_series_rejects_nonfinite_input() -> None:
    try:
        analyze_complexity_series(
            [
                {"size": 1, "cost": 1.0},
                {"size": 2, "cost": float("inf")},
                {"size": 4, "cost": 4.0},
            ]
        )
    except SourceAuditError as exc:
        assert "finite and positive" in str(exc)
    else:
        raise AssertionError("non-finite cost was accepted")


def test_complexity_series_rejects_unsafe_series_label() -> None:
    try:
        analyze_complexity_series(
            [
                {"series": "line\nbreak", "size": size, "cost": size}
                for size in (1, 2, 4)
            ]
        )
    except SourceAuditError as exc:
        assert "invalid series label" in str(exc)
    else:
        raise AssertionError("unsafe series label was accepted")


def test_paired_benchmark_trials_preserve_pairing_and_operations() -> None:
    result = analyze_paired_benchmark_trials(
        [
            {"candidate_cost": 0.50, "control_cost": 0.10, "operations": 100},
            {"candidate_cost": 0.55, "control_cost": 0.11, "operations": 100},
            {"candidate_cost": 0.45, "control_cost": 0.09, "operations": 100},
        ]
    )

    assert result["pair_count"] == 3
    assert result["median_paired_ratio"] == 5.0
    assert result["median_paired_delta"] == 0.4
    assert result["median_delta_per_operation"] == 0.004
    assert result["candidate_slower_pairs"] == 3
    assert result["network_access"] is False
    assert result["target_code_executed"] is False
