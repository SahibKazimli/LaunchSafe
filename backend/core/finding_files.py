"""Map findings to on-disk file keys and build minimal file bundles for fix mode.

Full-repo ``_files`` can be missing in edge cases (process boundaries, older
sessions). We always persist ``finding_files``: a subset of the repo containing
only sources tied to recorded findings, so Phase 2 can patch real code.
"""

from __future__ import annotations

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
    """Return 1-based line number from ``path:42``-style locations, if present."""
    loc = (location or "").strip().replace("\\", "/")
    if ":" not in loc:
        return None
    _base, _sep, last = loc.rpartition(":")
    if last.isdigit():
        return int(last)
    return None


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
