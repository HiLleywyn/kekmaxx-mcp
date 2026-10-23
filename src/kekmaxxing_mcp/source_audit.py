"""Bounded, offline helpers for authorized source-security research.

These helpers never contact a repository remote, execute target code, or claim
that a heuristic match is a vulnerability.  They are intended to make source
review snapshots and candidate triage reproducible without leaking local paths.
"""

from __future__ import annotations

import hashlib
import math
import re
import statistics
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
_SCHEDULE_RE = re.compile(
    r"\b(?:add_timer|del_timer|post_event|post(?:ed)?_event|queue_work|schedule|"
    r"set_timeout|event_handler|callback|async|uv_queue_work|uv_timer_start|"
    r"ngx_add_timer|ngx_post_event)\b",
    re.IGNORECASE,
)
_LIFETIME_RE = re.compile(
    r"\b(?:free|delete|destroy(?:_pool)?|cleanup|finalize|release|dispose|"
    r"refcount|reference_count|pool|teardown|abort)\b",
    re.IGNORECASE,
)
_CONTEXT_RE = re.compile(
    r"\b(?:ctx|context|data|handler|request|connection|session|task|event)\b",
    re.IGNORECASE,
)
_LOOP_RE = re.compile(r"\b(?:for|while)\s*\(")
_EXPENSIVE_RE = re.compile(
    r"(?:\b|_)(?:memcmp|strcmp|strncmp|strlen|strstr|memmem|regex|regexec|"
    r"pcre_exec|find|search|match|compare)\s*\(",
    re.IGNORECASE,
)


class SourceAuditError(ValueError):
    """Raised when a local source snapshot cannot be inspected safely."""


def _complexity_label(exponent: float) -> str:
    if exponent < 0.4:
        return "approximately_constant"
    if exponent < 1.35:
        return "approximately_linear"
    if exponent < 2.35:
        return "approximately_quadratic"
    if exponent < 3.35:
        return "approximately_cubic"
    return "super_cubic_or_unstable"


def analyze_complexity_series(
    observations: list[dict[str, object]],
    max_observations: int = 2_000,
) -> dict[str, object]:
    """Fit bounded empirical cost curves without executing or contacting a target.

    Each observation contains ``size``, ``cost``, and an optional short ``series``
    label. Repeated measurements at one size are reduced to their median before a
    log-log slope is fitted. The result is triage evidence, not asymptotic proof.
    """

    if not 3 <= max_observations <= 10_000:
        raise SourceAuditError("max_observations must be between 3 and 10000")
    if not 3 <= len(observations) <= max_observations:
        raise SourceAuditError("observations must contain between 3 and max_observations rows")

    grouped: dict[str, dict[int, list[float]]] = {}
    for index, row in enumerate(observations):
        if not isinstance(row, dict):
            raise SourceAuditError(f"observation {index} must be an object")
        unexpected = set(row) - {"series", "size", "cost"}
        if unexpected:
            raise SourceAuditError(f"observation {index} has unsupported fields")

        label = row.get("series", "default")
        size = row.get("size")
        cost = row.get("cost")
        if not isinstance(label, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", label
        ):
            raise SourceAuditError(f"observation {index} has an invalid series label")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise SourceAuditError(f"observation {index} size must be a positive integer")
        if not isinstance(cost, (int, float)) or isinstance(cost, bool):
            raise SourceAuditError(f"observation {index} cost must be numeric")
        numeric_cost = float(cost)
        if not math.isfinite(numeric_cost) or numeric_cost <= 0:
            raise SourceAuditError(f"observation {index} cost must be finite and positive")

        grouped.setdefault(label, {}).setdefault(size, []).append(numeric_cost)
        if len(grouped) > 32:
            raise SourceAuditError("observations may contain at most 32 series")

    series_results: list[dict[str, object]] = []
    for label in sorted(grouped):
        medians = [
            {
                "size": size,
                "median_cost": statistics.median(grouped[label][size]),
                "sample_count": len(grouped[label][size]),
            }
            for size in sorted(grouped[label])
        ]
        if len(medians) < 3:
            raise SourceAuditError(f"series {label!r} needs at least three distinct sizes")

        xs = [math.log(float(point["size"])) for point in medians]
        ys = [math.log(float(point["median_cost"])) for point in medians]
        x_mean = statistics.fmean(xs)
        y_mean = statistics.fmean(ys)
        denominator = sum((value - x_mean) ** 2 for value in xs)
        slope = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys, strict=True))
        slope /= denominator
        intercept = y_mean - slope * x_mean
        predicted = [intercept + slope * value for value in xs]
        residual = sum((actual - fitted) ** 2 for actual, fitted in zip(ys, predicted, strict=True))
        total = sum((actual - y_mean) ** 2 for actual in ys)
        r_squared = 1.0 if total == 0 else max(0.0, 1.0 - residual / total)

        local_exponents = [
            math.log(float(right["median_cost"]) / float(left["median_cost"]))
            / math.log(float(right["size"]) / float(left["size"]))
            for left, right in zip(medians, medians[1:], strict=False)
        ]
        series_results.append(
            {
                "series": label,
                "points": medians,
                "log_log_exponent": round(slope, 6),
                "r_squared": round(r_squared, 6),
                "median_local_exponent": round(statistics.median(local_exponents), 6),
                "classification": _complexity_label(slope),
            }
        )

    return {
        "schema_version": 1,
        "observation_count": len(observations),
        "series": series_results,
        "interpretation": (
            "Empirical log-log fits are validation aids, not proofs of algorithmic complexity. "
            "Preserve raw measurements, use same-size negative controls, and confirm the "
            "source-level operation count before making a security claim."
        ),
        "network_access": False,
        "target_code_executed": False,
    }


def _git(root: Path, *args: str, timeout: int = 20) -> bytes:
    try:
        completed = subprocess.run(
            [
                "git",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "submodule.recurse=false",
                "-C",
                str(root),
                *args,
            ],
            check=True,
            capture_output=True,
            timeout=timeout,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SourceAuditError(f"git command failed: {' '.join(args)}") from exc
    return completed.stdout


def _repo_root(repository: str) -> Path:
    candidate = Path(repository).expanduser()
    if not candidate.is_dir():
        raise SourceAuditError("repository must be an existing local directory")
    raw = _git(candidate, "rev-parse", "--show-toplevel").decode("utf-8", "replace").strip()
    root = Path(raw).resolve()
    if not root.is_dir():
        raise SourceAuditError("git did not return an existing repository root")
    return root


def _sanitize_origin(value: str) -> dict[str, str] | None:
    value = value.strip()
    if not value:
        return None
    if re.match(r"^[^/@:]+@[^/:]+:.+$", value):
        _user, remainder = value.split("@", 1)
        host, path = remainder.split(":", 1)
        path = re.split(r"[?#]", path, maxsplit=1)[0]
        return {"host": host.lower(), "repository": "/" + path.lstrip("/")}
    parts = urlsplit(value)
    if parts.scheme in {"http", "https", "ssh", "git"} and parts.hostname:
        return {"host": parts.hostname.lower(), "repository": "/" + parts.path.lstrip("/")}
    return {"host": "local", "repository": "redacted-local-origin"}


def _tracked_files(root: Path, max_files: int) -> list[str]:
    if not 1 <= max_files <= 500_000:
        raise SourceAuditError("max_files must be between 1 and 500000")
    names = [
        item.decode("utf-8", "surrogateescape")
        for item in _git(root, "ls-files", "-z", timeout=30).split(b"\0")
        if item
    ]
    if len(names) > max_files:
        raise SourceAuditError(f"repository has more than the max_files limit ({max_files})")
    return names


def source_snapshot_manifest(repository: str, max_files: int = 200_000) -> dict[str, object]:
    """Describe an immutable local Git snapshot without exposing its absolute path."""

    root = _repo_root(repository)
    tracked = _tracked_files(root, max_files)
    revision = _git(root, "rev-parse", "HEAD").decode().strip()
    tree_oid = _git(root, "rev-parse", "HEAD^{tree}").decode().strip()
    branch = _git(root, "branch", "--show-current").decode("utf-8", "replace").strip()
    index = _git(root, "ls-files", "-s", "-z", timeout=30)
    status = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all", timeout=30)
    entries = [entry for entry in status.split(b"\0") if entry]
    staged = len(
        [
            item
            for item in _git(
                root, "diff", "--no-ext-diff", "--no-textconv", "--cached", "--name-only", "-z"
            ).split(b"\0")
            if item
        ]
    )
    unstaged = len(
        [
            item
            for item in _git(
                root, "diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z"
            ).split(b"\0")
            if item
        ]
    )
    untracked = len(
        [
            item
            for item in _git(root, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
            if item
        ]
    )

    try:
        origin_raw = _git(root, "remote", "get-url", "origin").decode("utf-8", "replace")
    except SourceAuditError:
        origin_raw = ""

    return {
        "schema_version": 1,
        "repository_name": root.name,
        "revision": revision,
        "tree_oid": tree_oid,
        "branch": branch or None,
        "origin": _sanitize_origin(origin_raw),
        "tracked_file_count": len(tracked),
        "index_sha256": hashlib.sha256(index).hexdigest(),
        "status_sha256": hashlib.sha256(status).hexdigest(),
        "dirty": bool(entries),
        "change_counts": {
            "status_entries": len(entries),
            "staged": staged,
            "unstaged": unstaged,
            "untracked": untracked,
        },
        "network_access": False,
        "target_code_executed": False,
    }


def _source_files(root: Path, max_files: int, max_file_bytes: int) -> list[tuple[str, str]]:
    if not 1_024 <= max_file_bytes <= 5_000_000:
        raise SourceAuditError("max_file_bytes must be between 1024 and 5000000")
    result: list[tuple[str, str]] = []
    for relative in _tracked_files(root, max_files):
        path = root / relative
        if path.suffix.lower() not in _SOURCE_SUFFIXES or path.is_symlink() or not path.is_file():
            continue
        try:
            path.resolve().relative_to(root)
        except (OSError, ValueError):
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                continue
            result.append((Path(relative).as_posix(), path.read_text("utf-8", errors="replace")))
        except OSError:
            continue
    return result


def _excerpt(lines: list[str], start: int, end: int, max_chars: int = 1_200) -> str:
    rendered = "\n".join(
        f"{index + 1}: {lines[index].rstrip()}" for index in range(start, min(end, len(lines)))
    )
    if len(rendered) > max_chars:
        return rendered[: max_chars - 1] + "…"
    return rendered


def source_lifetime_hotspots(
    repository: str,
    max_results: int = 100,
    max_files: int = 20_000,
    max_file_bytes: int = 2_000_000,
) -> dict[str, object]:
    """Find C/C++ windows that combine async scheduling and lifetime operations."""

    if not 1 <= max_results <= 500:
        raise SourceAuditError("max_results must be between 1 and 500")
    root = _repo_root(repository)
    files = _source_files(root, max_files, max_file_bytes)
    matches: list[dict[str, object]] = []

    for relative, text in files:
        lines = text.splitlines()
        schedule_lines = [i for i, line in enumerate(lines) if _SCHEDULE_RE.search(line)]
        lifetime_lines = [i for i, line in enumerate(lines) if _LIFETIME_RE.search(line)]
        for scheduled in schedule_lines:
            nearby = [line for line in lifetime_lines if abs(line - scheduled) <= 24]
            if not nearby:
                continue
            anchor = min(nearby, key=lambda line: abs(line - scheduled))
            start = max(0, min(scheduled, anchor) - 5)
            end = min(len(lines), max(scheduled, anchor) + 6)
            window = "\n".join(lines[start:end])
            reasons = ["async_schedule_or_callback", "allocation_or_teardown_nearby"]
            if _CONTEXT_RE.search(window):
                reasons.append("raw_context_or_request_state_nearby")
            matches.append(
                {
                    "path": relative,
                    "line": scheduled + 1,
                    "related_line": anchor + 1,
                    "reason_tags": reasons,
                    "excerpt": _excerpt(lines, start, end),
                }
            )
            if len(matches) >= max_results:
                break
        if len(matches) >= max_results:
            break

    return {
        "schema_version": 1,
        "repository_name": root.name,
        "files_considered": len(files),
        "matches": matches,
        "truncated": len(matches) >= max_results,
        "interpretation": (
            "Heuristic review leads only. Each match requires source-to-sink reasoning, "
            "lifetime proof, negative controls, and local validation."
        ),
        "network_access": False,
        "target_code_executed": False,
    }


def source_complexity_hotspots(
    repository: str,
    max_results: int = 100,
    max_files: int = 20_000,
    max_file_bytes: int = 2_000_000,
) -> dict[str, object]:
    """Find nested-loop C/C++ windows containing potentially length-dependent work."""

    if not 1 <= max_results <= 500:
        raise SourceAuditError("max_results must be between 1 and 500")
    root = _repo_root(repository)
    files = _source_files(root, max_files, max_file_bytes)
    matches: list[dict[str, object]] = []

    for relative, text in files:
        lines = text.splitlines()
        loop_lines = [i for i, line in enumerate(lines) if _LOOP_RE.search(line)]
        expensive_lines = [i for i, line in enumerate(lines) if _EXPENSIVE_RE.search(line)]
        for expensive in expensive_lines:
            enclosing = [line for line in loop_lines if 0 <= expensive - line <= 20]
            if not enclosing:
                continue
            outer = [line for line in loop_lines if 0 <= enclosing[-1] - line <= 30]
            nested = len(set(enclosing + outer)) >= 2
            start = max(0, min(enclosing) - 4)
            end = min(len(lines), expensive + 6)
            matches.append(
                {
                    "path": relative,
                    "line": expensive + 1,
                    "reason_tags": [
                        "length_dependent_operation_inside_loop",
                        *(["nested_loop_window"] if nested else []),
                    ],
                    "excerpt": _excerpt(lines, start, end),
                }
            )
            if len(matches) >= max_results:
                break
        if len(matches) >= max_results:
            break

    return {
        "schema_version": 1,
        "repository_name": root.name,
        "files_considered": len(files),
        "matches": matches,
        "truncated": len(matches) >= max_results,
        "interpretation": (
            "Heuristic review leads only. Confirm attacker influence, asymptotic behavior, "
            "realistic input bounds, and worker impact with a disposable local harness."
        ),
        "network_access": False,
        "target_code_executed": False,
    }
