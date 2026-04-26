"""Semantic locate helpers: map LLM-proposed regions to **verified** substrings of
repo files using routes, symbols, fuzzy line match, and repo-wide needle search.

Used by :func:`fix_patch_helpers.resolve_locate_items` so step 2 still replaces
text that provably exists in the file.
"""

from __future__ import annotations

import re
from typing import Any
from difflib import SequenceMatcher
from .fix_state import PatchLocateRow


def _norm_crlf(s: str) -> str:
    return (s or "").replace("\r\n", "\n")


def _similar_line(line_a: str, line_b: str) -> float:
    line_a, line_b = line_a.strip(), line_b.strip()
    if not line_a or not line_b:
        return 0.0
    if line_a == line_b:
        return 1.0
    if line_a in line_b or line_b in line_a:
        return 0.92
    return SequenceMatcher(None, line_a, line_b).ratio()


def parse_http_route_hint(route_hint: str) -> tuple[str, str]:
    """Return (method_upper_or_empty, path_lower).

    Accepts strings like ``GET /users/{user_id}`` or ``/search/chunks``.
    """
    raw = (route_hint or "").strip()
    if not raw:
        return "", ""
    parts = raw.split(None, 1)
    if len(parts) == 2 and parts[0].upper() in frozenset(
        {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
    ):
        return parts[0].upper(), parts[1].strip().lower()
    return "", raw.strip().lower()


def _path_needles_for_search(path_lower: str) -> list[str]:
    if not path_lower:
        return []
    needles = [path_lower]
    # Strip FastAPI-style path params for broader search
    simplified = re.sub(r"\{[^}]+\}", "", path_lower)
    simplified = re.sub(r"/+", "/", simplified).strip("/")
    if simplified and simplified != path_lower:
        needles.append(simplified)
    # Last segment
    seg = path_lower.rstrip("/").split("/")[-1]
    if seg and seg not in needles:
        needles.append(seg)
    return needles


def extract_python_def_block(content: str, name: str) -> str | None:
    """Return source of ``def name`` / ``async def name`` including decorators above."""
    if not name.strip():
        return None
    lines = _norm_crlf(content).splitlines(True)
    pat = re.compile(rf"^(\s*)(async\s+)?def\s+{re.escape(name.strip())}\b")
    def_idx: int | None = None
    for line_index, line in enumerate(lines):
        if pat.match(line):
            def_idx = line_index
            break
    if def_idx is None:
        return None
    # Walk up to include decorators
    start = def_idx
    prev_line_index = def_idx - 1
    while prev_line_index >= 0:
        prev = lines[prev_line_index]
        stripped = prev.lstrip()
        if stripped.startswith("@"):
            start = prev_line_index
            prev_line_index -= 1
            continue
        if not prev.strip() or stripped.startswith("#"):
            prev_line_index -= 1
            continue
        break
    base_line = lines[def_idx]
    indent_match = re.match(r"^(\s*)", base_line)
    base_indent = len(indent_match.group(1).expandtabs()) if indent_match else 0
    block: list[str] = lines[start : def_idx + 1]
    for line_idx in range(def_idx + 1, len(lines)):
        line = lines[line_idx]
        if not line.strip():
            block.append(line)
            continue
        if line.lstrip().startswith("#"):
            block.append(line)
            continue
        cur_indent_match = re.match(r"^(\s*)", line)
        cur_indent = len(cur_indent_match.group(1).expandtabs()) if cur_indent_match else 0
        if cur_indent > base_indent:
            block.append(line)
            continue
        break
    text = "".join(block).strip("\n")
    return text if text else None


def expand_route_match_to_handler_block(content: str, match_start: int) -> str | None:
    """Given char offset of a route decorator match, expand to decorator(s) + following def."""
    text = _norm_crlf(content)
    if match_start < 0 or match_start >= len(text):
        return None
    line_no = text.count("\n", 0, match_start)
    lines = text.splitlines(True)
    # Walk up to first @ starting a small window
    decorator_start_idx = line_no
    while decorator_start_idx > 0 and lines[decorator_start_idx - 1].lstrip().startswith("#"):
        decorator_start_idx -= 1
    while decorator_start_idx > 0:
        prev = lines[decorator_start_idx - 1]
        if prev.lstrip().startswith("@"):
            decorator_start_idx -= 1
            continue
        if not prev.strip():
            decorator_start_idx -= 1
            continue
        break
    # Find following def
    def_idx: int | None = None
    for scan_line_idx in range(line_no, len(lines)):
        if re.match(r"^\s*(async\s+)?def\s+\w+\b", lines[scan_line_idx]):
            def_idx = scan_line_idx
            break
    if def_idx is None:
        # fall back: several lines from match line
        chunk = "".join(lines[max(0, line_no - 2) : min(len(lines), line_no + 25)])
        return chunk.strip() or None
    name_match = re.match(r"^\s*(async\s+)?def\s+(\w+)\b", lines[def_idx])
    symbol_name = name_match.group(2) if name_match else ""
    if symbol_name:
        whole = extract_python_def_block(text, symbol_name)
        if whole:
            return whole
    return "".join(lines[decorator_start_idx : def_idx + 25]).strip() or None


def span_for_route_hint(content: str, route_hint: str) -> str | None:
    """Locate a FastAPI/Flask-style route and return a handler-sized block."""
    _method, path_lower = parse_http_route_hint(route_hint)
    if not path_lower:
        return None
    needles = _path_needles_for_search(path_lower)
    text = _norm_crlf(content)
    lowered = text.lower()
    for needle in needles:
        if not needle:
            continue
        pos = lowered.find(needle.lower())
        if pos < 0:
            continue
        block = expand_route_match_to_handler_block(text, pos)
        if block:
            return block
    # Regex fallbacks (FastAPI / APIRouter)
    esc = re.escape(path_lower.split("?")[0].rstrip("/"))
    esc = esc.replace(r"\{", r"\{").replace(r"\}", r"\}")
    patterns = [
        rf"@\w+\.(get|post|put|patch|delete|route)\([\"']{esc}",
        rf"['\"]{re.escape(path_lower)}['\"]",
    ]
    for pat in patterns:
        regex_match = re.search(pat, text, re.IGNORECASE)
        if regex_match:
            expanded_block = expand_route_match_to_handler_block(text, regex_match.start())
            if expanded_block:
                return expanded_block
    return None


def fuzzy_resolve_snippet(proposed: str, content: str, min_line_ratio: float = 0.72) -> str | None:
    """Align proposed lines to a contiguous region in *content* by per-line similarity."""
    prop_lines = [ln.rstrip() for ln in _norm_crlf(proposed).splitlines()]
    prop_lines = [ln for ln in prop_lines if ln.strip()]
    if len(prop_lines) < 2:
        return None
    file_lines = _norm_crlf(content).splitlines()
    best_span: tuple[int, int] | None = None
    best_score = 0
    for window_start in range(len(file_lines)):
        if _similar_line(file_lines[window_start], prop_lines[0]) < min_line_ratio:
            continue
        prop_line_index = 0
        file_line_index = window_start
        matched = 0
        while prop_line_index < len(prop_lines) and file_line_index < len(file_lines):
            if (
                _similar_line(file_lines[file_line_index], prop_lines[prop_line_index])
                >= min_line_ratio
            ):
                matched += 1
                prop_line_index += 1
            file_line_index += 1
        need = max(2, (len(prop_lines) + 1) // 2)
        if matched >= need and matched > best_score:
            best_score = matched
            best_span = (window_start, file_line_index)
    if best_span is None:
        return None
    span_start, span_end = best_span
    return "\n".join(file_lines[span_start:span_end])


def resolve_row_to_verified_snippet(
    row: PatchLocateRow,
    file_content: str,
) -> tuple[str, float] | None:
    """Return ``(verbatim_snippet, confidence)`` if *file_content* contains the snippet."""
    content = _norm_crlf(file_content)
    proposed = _norm_crlf(row.original_snippet or "")
    if proposed.strip() and proposed in content:
        return proposed, 1.0

    for anchor_symbol in row.anchor_symbols or []:
        block = extract_python_def_block(content, anchor_symbol.strip())
        if block:
            return block, 0.88

    if row.anchor_route.strip():
        block = span_for_route_hint(content, row.anchor_route)
        if block:
            return _norm_crlf(block), 0.85

    if proposed.strip():
        fuzzy = fuzzy_resolve_snippet(proposed, content)
        if fuzzy and fuzzy in content:
            return fuzzy, 0.75

    return None


def repo_wide_search_evidence(
    files: dict[str, str],
    needles: list[str],
    *,
    max_lines: int = 24,
) -> str:
    """Collect up to *max_lines* ``path:line: text`` hits across the stash (for no-op proof)."""
    hits: list[str] = []
    seen: set[tuple[str, int]] = set()
    for needle in needles:
        needle_trimmed = (needle or "").strip()
        if len(needle_trimmed) < 2:
            continue
        needle_lower = needle_trimmed.lower()
        for path, body in sorted(files.items()):
            if needle_lower not in _norm_crlf(body).lower():
                continue
            for line_number, line in enumerate(_norm_crlf(body).splitlines(), 1):
                if needle_lower in line.lower():
                    path_line_key = (path, line_number)
                    if path_line_key in seen:
                        continue
                    seen.add(path_line_key)
                    hits.append(f"{path}:{line_number}: {line.strip()[:240]}")
                    if len(hits) >= max_lines:
                        return "\n".join(hits)
    if not hits:
        return ""
    return "\n".join(hits)


def collect_evidence_needles_from_findings(findings: list[dict[str, Any]]) -> list[str]:
    """Build search needles from finding locations and narrative (routes, paths, symbols)."""
    needles: list[str] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        for key in ("location", "module", "title"):
            raw = str(finding.get(key) or "").strip()
            if raw and raw.lower() not in ("unknown", "?", "n/a", "none"):
                needles.append(raw.split(":")[0].strip())
        blob = " ".join(
            str(finding.get(field_name) or "")
            for field_name in ("title", "description", "fix")
        )
        for route_match in re.finditer(
            r"(?:GET|POST|PUT|PATCH|DELETE|HEAD)\s+(/\S+)", blob, re.I
        ):
            needles.append(route_match.group(0).strip())
        for path_match in re.finditer(r"['\"](/[a-zA-Z0-9_\-/{}\.]+)['\"]", blob):
            needles.append(path_match.group(1))
        for def_match in re.finditer(
            r"\b(def|async def)\s+([a-zA-Z_][a-zA-Z0-9_]*)\b", blob
        ):
            needles.append(def_match.group(2))
    seen: set[str] = set()
    out: list[str] = []
    for needle_candidate in needles:
        trimmed = needle_candidate.strip()
        if len(trimmed) < 2 or trimmed.lower() in seen:
            continue
        seen.add(trimmed.lower())
        out.append(trimmed)
        if len(out) >= 48:
            break
    return out
