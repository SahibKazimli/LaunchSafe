"""Map findings to on-disk file keys and build minimal file bundles for fix mode.

Full-repo ``_files`` can be missing in edge cases (process boundaries, older
sessions). We always persist ``finding_files``: a subset of the repo containing
only sources tied to recorded findings, so Phase 2 can patch real code.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from agents.prompts.fix_prompts import (
    FIX_EXCERPT_TRUNCATED_HEAD_NOTE,
    format_fix_excerpt_full_file,
    format_fix_excerpt_head_only,
    format_fix_excerpt_large_window,
    format_fix_excerpt_narrow_cited,
)
from agents.schemas import coerce_highlight_line_ranges


def _finding_narrative_blob(finding: dict) -> str:
    """Text used to guess file paths when ``location`` is missing or wrong."""
    parts = [
        str(finding.get("location") or ""),
        str(finding.get("module") or ""),
        str(finding.get("title") or ""),
        str(finding.get("description") or ""),
        str(finding.get("fix") or ""),
    ]
    return " ".join(parts).lower()


def infer_paths_from_finding_text(
    findings: list[dict],
    files: dict[str, str],
    *,
    max_paths: int = 16,
) -> list[str]:
    """Find repo keys whose path appears in finding text (full path or basename with extension).

    Use when structured ``location`` is empty, ``unknown``, or does not match ingest keys.
    """
    if not findings or not files:
        return []
    blob = " ".join(
        _finding_narrative_blob(finding)
        for finding in findings
        if isinstance(finding, dict)
    )
    if not blob.strip():
        return []

    hits: list[tuple[int, str]] = []
    for file_key in files:
        file_key_norm = file_key.replace("\\", "/").lower()
        if file_key_norm in blob:
            hits.append((-len(file_key), file_key))
            continue
        base = file_key_norm.split("/")[-1]
        if "." in base and len(base) >= 5 and base in blob:
            hits.append((-len(file_key), file_key))

    seen: set[str] = set()
    out: list[str] = []
    for _neglen, file_key in sorted(hits):
        if file_key not in seen:
            seen.add(file_key)
            out.append(file_key)
        if len(out) >= max_paths:
            break
    return out


def normalize_path_hint(location: str) -> str:
    """Strip noise, unify slashes, and drop trailing :line when line is numeric."""
    loc = (location or "").strip().replace("\\", "/")
    if not loc or loc.startswith("—") or "absent" in loc.lower():
        return ""
    if ":" in loc:
        _base, _sep, last = loc.rpartition(":")
        if last.isdigit():
            loc = _base.strip()
    return loc.strip()


def find_file_content(path: str, files: dict[str, str]) -> tuple[str, str]:
    """Find file content by path, handling zip root prefixes and varying slashes."""
    path = normalize_path_hint(path) if path else ""
    if not path:
        return "", ""
    if path in files:
        return path, files[path]

    path_suffix = "/" + path.lstrip("/")
    for file_key, file_content in files.items():
        if ("/" + file_key).endswith(path_suffix) or path_suffix.endswith("/" + file_key):
            return file_key, file_content

    path_lower = path_suffix.lower()
    for file_key, file_content in files.items():
        if ("/" + file_key).lower().endswith(path_lower):
            return file_key, file_content

    return path, ""


def resolve_path_to_canonical_key(path_hint: str, files: dict[str, str]) -> str:
    """Map a finding location / planner hint to a key present in ``files``."""
    raw = (path_hint or "").strip()
    if raw.lower() in ("", "unknown", "?", "n/a", "none"):
        return ""
    hint = normalize_path_hint(path_hint)
    if not hint or not files:
        return ""
    file_key, file_content = find_file_content(hint, files)
    if file_content:
        return file_key
    base = hint.split("/")[-1].lower()
    if not base:
        return ""
    matches = [
        candidate_key
        for candidate_key in files
        if candidate_key.lower() == base
        or candidate_key.lower().endswith("/" + base)
    ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        hint_lower = (path_hint or "").lower().replace("\\", "/")
        for candidate_key in sorted(matches, key=lambda path: -len(path)):
            if candidate_key.lower() in hint_lower:
                return candidate_key
        # Deterministic fallback: prefer longest path (usually more specific)
        return sorted(matches, key=lambda path: -len(path))[0]
    return ""


def resolve_paths_for_findings(
    findings: list[dict],
    files: dict[str, str],
) -> list[str]:
    """Ordered unique repo paths for a list of findings."""
    out: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        resolved_file_key = resolve_path_to_canonical_key(
            finding.get("location", ""), files
        )
        if resolved_file_key and resolved_file_key not in seen:
            out.append(resolved_file_key)
            seen.add(resolved_file_key)
    for inferred_file_key in infer_paths_from_finding_text(findings, files):
        if inferred_file_key not in seen:
            out.append(inferred_file_key)
            seen.add(inferred_file_key)
    return out


def build_finding_file_bundle(
    all_files: dict[str, str],
    findings: list[dict],
) -> dict[str, str]:
    """Copy full contents for every file referenced by at least one finding."""
    if not all_files or not findings:
        return {}
    out: dict[str, str] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        for hint in (
            finding.get("location", ""),
            finding.get("file_path", ""),
            finding.get("path", ""),
        ):
            if not hint or not isinstance(hint, str):
                continue
            resolved_file_key = resolve_path_to_canonical_key(hint, all_files)
            if resolved_file_key and resolved_file_key in all_files:
                out[resolved_file_key] = all_files[resolved_file_key]
        for inferred_file_key in infer_paths_from_finding_text(
            [finding], all_files, max_paths=8
        ):
            if inferred_file_key in all_files:
                out[inferred_file_key] = all_files[inferred_file_key]
    return out


def parse_line_number_from_location(location: str) -> int | None:
    """Return 1-based line from ``...path:12`` or ``...path:10-20`` (range: first line)."""
    loc = (location or "").strip().replace("\\", "/")
    if not loc:
        return None
    range_match = re.search(r":(\d+)-(\d+)\s*$", loc)
    if range_match:
        return int(range_match.group(1))
    line_match = re.search(r":(\d+)\s*$", loc)
    if line_match:
        return int(line_match.group(1))
    return None


def _coerce_positive_int(raw_value: Any) -> int | None:
    if raw_value is None or raw_value is False:
        return None
    try:
        parsed_int = int(raw_value)
    except (TypeError, ValueError):
        return None
    return parsed_int if parsed_int >= 1 else None


def _is_weak_anchor_line(line_text: str) -> bool:
    """True only for punctuation/whitespace-only lines (e.g. a lone `)` or `,`).

    If any letter or digit appears, the model chose a real line, do not nudge, so the
    highlight matches `location:line` even when that line is wrong (that is a model issue).
    """
    code_text = line_text.rstrip("\n").split("#", 1)[0].strip()
    if not code_text:
        return True
    if re.search(r"[0-9A-Za-z]", code_text):
        return False
    return True


def _nudge_cited_off_weak_anchor(
    raw_lines: list[str],
    cited: int,
    *,
    max_up: int = 3,
) -> int:
    """Nudge at most a few lines up, only from delimiter-only rows."""
    line_count = len(raw_lines)
    cited_line = min(max(1, cited), line_count)
    steps_up = 0
    while (
        steps_up < max_up
        and cited_line > 1
        and _is_weak_anchor_line(raw_lines[cited_line - 1])
    ):
        cited_line -= 1
        steps_up += 1
    return cited_line


_EXT_TO_HLJS_LANG: dict[str, str] = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".json": "json",
    ".md": "markdown",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".tf": "hcl",
    ".tfvars": "hcl",
    ".hcl": "hcl",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".swift": "swift",
    ".sql": "sql",
    ".sh": "bash",
    ".bash": "bash",
    ".zsh": "bash",
    ".dockerfile": "dockerfile",
    "dockerfile": "dockerfile",
    ".xml": "xml",
    ".html": "xml",
    ".css": "css",
    ".scss": "scss",
    ".less": "less",
    ".vue": "html",
    ".svelte": "html",
    ".toml": "ini",
    ".ini": "ini",
    ".cfg": "ini",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
}


def _line_set_to_contiguous_runs(line_set: set[int]) -> list[tuple[int, int]]:
    if not line_set:
        return []
    sorted_line_numbers = sorted(line_set)
    runs: list[tuple[int, int]] = []
    run_start = sorted_line_numbers[0]
    run_end = sorted_line_numbers[0]
    for line_number in sorted_line_numbers[1:]:
        if line_number == run_end + 1:
            run_end = line_number
        else:
            runs.append((run_start, run_end))
            run_start = run_end = line_number
    runs.append((run_start, run_end))
    return runs


def _clamp_ranges_in_file(
    ranges: list[tuple[int, int]], line_count: int
) -> list[tuple[int, int]]:
    if not line_count:
        return []
    clamped: list[tuple[int, int]] = []
    for range_start, range_end in ranges:
        start_line, end_line = min(range_start, range_end), max(range_start, range_end)
        start_line = min(max(1, start_line), line_count)
        end_line = min(max(1, end_line), line_count)
        if start_line > end_line:
            start_line, end_line = end_line, start_line
        clamped.append((start_line, end_line))
    return clamped


def _file_lines_from_ranges(
    ranges: list[tuple[int, int]], line_count: int
) -> set[int]:
    line_numbers: set[int] = set()
    for range_start, range_end in _clamp_ranges_in_file(ranges, line_count):
        line_numbers.update(range(range_start, range_end + 1))
    return line_numbers


def _snippet_line_window(
    line_count: int,
    cover_lo: int,
    cover_hi: int,
    cited: int,
    *,
    line_margin: int,
    max_window_lines: int,
) -> tuple[int, int]:
    half = min(line_margin, max_window_lines // 2)
    span_lo, span_hi = min(cover_lo, cover_hi), max(cover_lo, cover_hi)
    window_start = max(1, span_lo - half)
    window_end = min(line_count, span_hi + half)
    if window_end - window_start + 1 > max_window_lines:
        window_start = max(1, cited - (max_window_lines // 2))
        window_end = min(line_count, window_start + max_window_lines - 1)
        if window_end - window_start + 1 < max_window_lines and window_start > 1:
            window_start = max(1, window_end - max_window_lines + 1)
    if not (window_start <= cited <= window_end):
        span = min(max_window_lines, line_count)
        window_start = max(1, cited - span // 2)
        window_end = min(line_count, window_start + span - 1)
        if window_end - window_start + 1 < span and window_start > 1:
            window_start = max(1, window_end - span + 1)
    if cited < window_start:
        window_start = max(1, cited)
    if cited > window_end:
        window_end = min(line_count, cited)
    if window_end < window_start:
        window_start = window_end = cited
    return window_start, window_end


def infer_code_language_from_path(file_key: str) -> str:
    """Map file path to a highlight.js / Prism style language id for the report UI."""
    name = (file_key or "").split("/")[-1].lower()
    if not name or "." not in name:
        if name == "dockerfile":
            return "dockerfile"
        return "plaintext"
    suf = Path(name).suffix.lower()
    if not suf and name:
        if name == "dockerfile":
            return "dockerfile"
        return "plaintext"
    return _EXT_TO_HLJS_LANG.get(suf, "plaintext")


def enrich_finding_code_context(
    finding: dict[str, Any],
    all_files: dict[str, str],
    *,
    line_margin: int = 50,
    max_window_lines: int = 200,
) -> dict[str, Any]:
    """Attach a wide source excerpt + line metadata for the report code modal.

    Only populates when ``location`` resolves to a file and a 1-based line number.
    """
    enriched: dict[str, Any] = dict(finding)
    if not all_files or not isinstance(finding, dict):
        return enriched

    canonical_file_key = resolve_path_to_canonical_key(
        finding.get("location", ""), all_files
    )
    if not canonical_file_key or canonical_file_key not in all_files:
        return enriched

    loc = str(finding.get("location", "") or "")
    line_from_loc = parse_line_number_from_location(loc)
    line_from_field = _coerce_positive_int(
        finding.get("line_start")
    ) or _coerce_positive_int(finding.get("line_end"))
    # Always prefer the line embedded in `location` (`path:line`). It is a single
    # citation; optional `line_start` from structured output often drifts and
    # would override with a different number, centering the wrong code in the modal.
    if line_from_loc is not None:
        line = line_from_loc
    else:
        line = line_from_field
    if line is None:
        return enriched

    file_text = all_files[canonical_file_key]
    raw_lines = file_text.splitlines(keepends=True)
    line_count = len(raw_lines)
    if line_count == 0:
        return enriched

    cited = min(max(1, line), line_count)
    cited = _nudge_cited_off_weak_anchor(raw_lines, cited)

    raw_ranges = coerce_highlight_line_ranges(finding.get("highlight_line_ranges"))
    model_ranges = _clamp_ranges_in_file(list(raw_ranges or []), line_count)
    highlight_file_lines: set[int] = set()
    if model_ranges:
        highlight_file_lines = _file_lines_from_ranges(model_ranges, line_count)
    if not highlight_file_lines:
        for file_line in (cited - 1, cited, cited + 1):
            if 1 <= file_line <= line_count:
                highlight_file_lines.add(file_line)
    if not highlight_file_lines:
        highlight_file_lines.add(cited)
    highlight_file_lines.add(cited)

    min_highlight_line = min(highlight_file_lines)
    max_highlight_line = max(highlight_file_lines)
    coverage_low_line = min(min_highlight_line, cited)
    coverage_high_line = max(max_highlight_line, cited)
    window_start, window_end = _snippet_line_window(
        line_count,
        coverage_low_line,
        coverage_high_line,
        cited,
        line_margin=line_margin,
        max_window_lines=max_window_lines,
    )
    lines_visible_in_excerpt = {
        line for line in highlight_file_lines if window_start <= line <= window_end
    }
    if not lines_visible_in_excerpt and window_start <= cited <= window_end:
        lines_visible_in_excerpt.add(cited)
    if not lines_visible_in_excerpt:
        lines_visible_in_excerpt = (
            {cited} if window_start <= cited <= window_end else set()
        )

    snippet_relative_line_indices = sorted(
        {line - window_start + 1 for line in lines_visible_in_excerpt}
    )
    if not snippet_relative_line_indices and window_start <= cited <= window_end:
        snippet_relative_line_indices = [cited - window_start + 1]

    snippet = "".join(raw_lines[window_start - 1 : window_end])
    enriched["file_path"] = canonical_file_key
    enriched["line_start"] = min_highlight_line
    enriched["line_end"] = max_highlight_line
    enriched["snippet"] = snippet
    enriched["highlight_lines"] = snippet_relative_line_indices
    enriched["snippet_start_line"] = window_start
    enriched["code_language"] = infer_code_language_from_path(canonical_file_key)
    enriched["highlight_line_ranges"] = [
        list(run) for run in _line_set_to_contiguous_runs(highlight_file_lines)
    ]
    if highlight_file_lines - lines_visible_in_excerpt:
        enriched["code_highlight_truncated"] = True
    return enriched


def enrich_findings_code_context(
    findings: list[dict],
    all_files: dict[str, str],
) -> list[dict]:
    """Enrich every finding with optional code context fields."""
    if not all_files or not findings:
        return [dict(finding) for finding in findings] if findings else []
    return [
        enrich_finding_code_context(finding, all_files)
        for finding in findings
        if isinstance(finding, dict)
    ]


def build_excerpt_for_fix_prompt(
    matched_path: str,
    content: str,
    group_findings: list[dict],
    files: dict[str, str],
    *,
    full_file_max_chars: int = 200_000,
    head_limit: int = 14_000,
    line_margin: int = 30,
    narrow_to_cited_region: bool = False,
) -> str:
    """Build prompt text for the patch model.

    Prefer the **complete ingested file** when it fits ``full_file_max_chars``
    (same bytes we already store in scan/fix context). Otherwise use a line
    window around cited locations, then a head truncation.

    If ``narrow_to_cited_region`` is True and at least one finding cites a line
    in this file, always use the line window (never the whole file) so the
    model focuses on the vulnerable region.
    """
    raw_file_lines = content.splitlines(keepends=True)
    line_count = len(raw_file_lines)
    cited_line_numbers: list[int] = []
    for group_finding in group_findings:
        if not isinstance(group_finding, dict):
            continue
        canonical_file_key = resolve_path_to_canonical_key(
            group_finding.get("location", ""), files
        )
        if canonical_file_key != matched_path:
            continue
        location_line = parse_line_number_from_location(
            group_finding.get("location", "")
        )
        if location_line is not None and location_line >= 1:
            cited_line_numbers.append(location_line)

    if narrow_to_cited_region and cited_line_numbers and line_count > 0:
        window_start = max(1, min(cited_line_numbers) - line_margin)
        window_end = min(line_count, max(cited_line_numbers) + line_margin)
        excerpt_text = "".join(raw_file_lines[window_start - 1 : window_end])
        return format_fix_excerpt_narrow_cited(
            matched_path, window_start, window_end, line_count, excerpt_text
        )

    if len(content) <= full_file_max_chars:
        return format_fix_excerpt_full_file(
            matched_path, line_count, len(content), content
        )

    if cited_line_numbers and line_count > 0:
        window_start = max(1, min(cited_line_numbers) - line_margin)
        window_end = min(line_count, max(cited_line_numbers) + line_margin)
        excerpt_text = "".join(raw_file_lines[window_start - 1 : window_end])
        return format_fix_excerpt_large_window(
            matched_path, window_start, window_end, line_count, excerpt_text
        )

    excerpt_text = content[:head_limit]
    if len(content) > head_limit:
        excerpt_text += FIX_EXCERPT_TRUNCATED_HEAD_NOTE
    return format_fix_excerpt_head_only(
        matched_path, line_count, len(content), excerpt_text
    )


def merge_scan_files_for_fix(fix_session: dict[str, Any], scan: dict[str, Any]) -> dict[str, str]:
    """Merge full-repo snapshot with per-finding file bundle (bundle wins on key clash)."""
    if fix_session.get("snapshot_files") is not None:
        main = dict(fix_session.get("snapshot_files") or {})
    else:
        main = dict(scan.get("_files") or {})
    if fix_session.get("snapshot_finding_files") is not None:
        sub = dict(fix_session.get("snapshot_finding_files") or {})
    else:
        sub = dict(scan.get("finding_files") or {})
    return {**main, **sub}
