from __future__ import annotations

import subprocess
from pathlib import Path

from kekmaxxing_mcp.source_audit import (
    source_complexity_hotspots,
    source_lifetime_hotspots,
    source_snapshot_manifest,
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
