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
        _finding_narrative_blob(f) for f in findings if isinstance(f, dict)
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
    key, content = find_file_content(hint, files)
    if content:
        return key
    base = hint.split("/")[-1].lower()
    if not base:
        return ""
    matches = [
        fk
        for fk in files
        if fk.lower() == base or fk.lower().endswith("/" + base)
    ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        hint_lower = (path_hint or "").lower().replace("\\", "/")
        for fk in sorted(matches, key=lambda x: -len(x)):
            if fk.lower() in hint_lower:
                return fk
        # Deterministic fallback: prefer longest path (usually more specific)
        return sorted(matches, key=lambda x: -len(x))[0]
    return ""


def resolve_paths_for_findings(
    findings: list[dict],
    files: dict[str, str],
) -> list[str]:
    """Ordered unique repo paths for a list of findings."""
    out: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        key = resolve_path_to_canonical_key(finding.get("location", ""), files)
        if key and key not in seen:
            out.append(key)
            seen.add(key)
    for key in infer_paths_from_finding_text(findings, files):
        if key not in seen:
            out.append(key)
            seen.add(key)
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
            key = resolve_path_to_canonical_key(hint, all_files)
            if key and key in all_files:
                out[key] = all_files[key]
        for key in infer_paths_from_finding_text([finding], all_files, max_paths=8):
            if key in all_files:
                out[key] = all_files[key]
    return out


def parse_line_number_from_location(location: str) -> int | None:
    """Return 1-based line from ``...path:12`` or ``...path:10-20`` (range: first line)."""
    loc = (location or "").strip().replace("\\", "/")
    if not loc:
        return None
    m = re.search(r":(\d+)-(\d+)\s*$", loc)
    if m:
        return int(m.group(1))
    m = re.search(r":(\d+)\s*$", loc)
    if m:
        return int(m.group(1))
    return None


def _coerce_positive_int(x: Any) -> int | None:
    if x is None or x is False:
        return None
    try:
        v = int(x)
    except (TypeError, ValueError):
        return None
    return v if v >= 1 else None


def _is_weak_anchor_line(line_text: str) -> bool:
    """Model output often points at a closing `)}];` or punctuation-only line — nudge to real code.

    A line is **substantive** if (after stripping end-of-line comments) it has a word
    (2+ letters) or a 3+ digit number (e.g. status code on its own).
    """
    t = line_text.rstrip("\n").split("#", 1)[0].strip()
    if not t:
        return True
    if re.search(r"[A-Za-z]{2,}", t):
        return False
    if re.search(r"^\d{3,}$", t):
        return False
    # Don’t nudge off lines that contain multi-digit numbers (e.g. real line-no labels,
    # `user_id: 10`, or similar); avoids massive upward walks on synthetic "L12" test lines.
    if re.search(r"\d{2,}", t):
        return False
    return True


def _nudge_cited_off_weak_anchor(
    raw_lines: list[str],
    cited: int,
    *,
    max_up: int = 35,
) -> int:
    """If the reported line is only delimiters, walk up to a substantive line."""
    n = len(raw_lines)
    c = min(max(1, cited), n)
    up = 0
    while up < max_up and c > 1 and _is_weak_anchor_line(raw_lines[c - 1]):
        c -= 1
        up += 1
    return c


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
    out: dict[str, Any] = dict(finding)
    if not all_files or not isinstance(finding, dict):
        return out

    key = resolve_path_to_canonical_key(finding.get("location", ""), all_files)
    if not key or key not in all_files:
        return out

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
        return out

    content = all_files[key]
    raw_lines = content.splitlines(keepends=True)
    n = len(raw_lines)
    if n == 0:
        return out

    cited = min(max(1, line), n)
    cited = _nudge_cited_off_weak_anchor(raw_lines, cited)
    half = min(line_margin, max_window_lines // 2)
    lo = max(1, cited - half)
    hi = min(n, cited + half)
    if hi - lo + 1 > max_window_lines:
        lo = max(1, cited - (max_window_lines // 2))
        hi = min(n, lo + max_window_lines - 1)
        if hi - lo + 1 < max_window_lines:
            lo = max(1, hi - max_window_lines + 1)
    if not (lo <= cited <= hi):
        span = min(max_window_lines, n)
        lo = max(1, cited - span // 2)
        hi = min(n, lo + span - 1)
        if hi - lo + 1 < span and lo > 1:
            lo = max(1, hi - span + 1)
    if cited < lo:
        lo = max(1, cited)
    if cited > hi:
        hi = min(n, cited)
    if hi < lo:
        lo = hi = cited

    snippet = "".join(raw_lines[lo - 1 : hi])
    rel_highlight = [cited - lo + 1]

    out["file_path"] = key
    out["line_start"] = cited
    out["line_end"] = cited
    out["snippet"] = snippet
    out["highlight_lines"] = rel_highlight
    out["snippet_start_line"] = lo
    out["code_language"] = infer_code_language_from_path(key)
    return out


def enrich_findings_code_context(
    findings: list[dict],
    all_files: dict[str, str],
) -> list[dict]:
    """Enrich every finding with optional code context fields."""
    if not all_files or not findings:
        return [dict(f) for f in findings] if findings else []
    return [enrich_finding_code_context(f, all_files) for f in findings if isinstance(f, dict)]


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
    lines = content.splitlines(keepends=True)
    n = len(lines)
    line_nums: list[int] = []
    for gf in group_findings:
        if not isinstance(gf, dict):
            continue
        fk = resolve_path_to_canonical_key(gf.get("location", ""), files)
        if fk != matched_path:
            continue
        ln = parse_line_number_from_location(gf.get("location", ""))
        if ln is not None and ln >= 1:
            line_nums.append(ln)

    if narrow_to_cited_region and line_nums and n > 0:
        lo = max(1, min(line_nums) - line_margin)
        hi = min(n, max(line_nums) + line_margin)
        excerpt = "".join(lines[lo - 1 : hi])
        return format_fix_excerpt_narrow_cited(matched_path, lo, hi, n, excerpt)

    if len(content) <= full_file_max_chars:
        return format_fix_excerpt_full_file(matched_path, n, len(content), content)

    if line_nums and n > 0:
        lo = max(1, min(line_nums) - line_margin)
        hi = min(n, max(line_nums) + line_margin)
        excerpt = "".join(lines[lo - 1 : hi])
        return format_fix_excerpt_large_window(matched_path, lo, hi, n, excerpt)

    excerpt = content[:head_limit]
    if len(content) > head_limit:
        excerpt += FIX_EXCERPT_TRUNCATED_HEAD_NOTE
    return format_fix_excerpt_head_only(matched_path, n, len(content), excerpt)


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
