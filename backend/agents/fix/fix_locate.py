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


def _similar_line(a: str, b: str) -> float:
    a, b = a.strip(), b.strip()
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    if a in b or b in a:
        return 0.92
    return SequenceMatcher(None, a, b).ratio()


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
    for i, line in enumerate(lines):
        if pat.match(line):
            def_idx = i
            break
    if def_idx is None:
        return None
    # Walk up to include decorators
    start = def_idx
    j = def_idx - 1
    while j >= 0:
        prev = lines[j]
        stripped = prev.lstrip()
        if stripped.startswith("@"):
            start = j
            j -= 1
            continue
        if not prev.strip() or stripped.startswith("#"):
            j -= 1
            continue
        break
    base_line = lines[def_idx]
    indent_match = re.match(r"^(\s*)", base_line)
    base_indent = len(indent_match.group(1).expandtabs()) if indent_match else 0
    block: list[str] = lines[start : def_idx + 1]
    for k in range(def_idx + 1, len(lines)):
        ln = lines[k]
        if not ln.strip():
            block.append(ln)
            continue
        if ln.lstrip().startswith("#"):
            block.append(ln)
            continue
        cur_m = re.match(r"^(\s*)", ln)
        cur_indent = len(cur_m.group(1).expandtabs()) if cur_m else 0
        if cur_indent > base_indent:
            block.append(ln)
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
    i = line_no
    while i > 0 and lines[i - 1].lstrip().startswith("#"):
        i -= 1
    while i > 0:
        prev = lines[i - 1]
        if prev.lstrip().startswith("@"):
            i -= 1
            continue
        if not prev.strip():
            i -= 1
            continue
        break
    # Find following def
    def_idx: int | None = None
    for j in range(line_no, len(lines)):
        if re.match(r"^\s*(async\s+)?def\s+\w+\b", lines[j]):
            def_idx = j
            break
    if def_idx is None:
        # fall back: several lines from match line
        chunk = "".join(lines[max(0, line_no - 2) : min(len(lines), line_no + 25)])
        return chunk.strip() or None
    name_m = re.match(r"^\s*(async\s+)?def\s+(\w+)\b", lines[def_idx])
    sym = name_m.group(2) if name_m else ""
    if sym:
        whole = extract_python_def_block(text, sym)
        if whole:
            return whole
    return "".join(lines[i : def_idx + 25]).strip() or None


def span_for_route_hint(content: str, route_hint: str) -> str | None:
    """Locate a FastAPI/Flask-style route and return a handler-sized block."""
    _method, path_lower = parse_http_route_hint(route_hint)
    if not path_lower:
        return None
    needles = _path_needles_for_search(path_lower)
    text = _norm_crlf(content)
    lowered = text.lower()
    for nd in needles:
        if not nd:
            continue
        pos = lowered.find(nd.lower())
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
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            b = expand_route_match_to_handler_block(text, m.start())
            if b:
                return b
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
    for i in range(len(file_lines)):
        if _similar_line(file_lines[i], prop_lines[0]) < min_line_ratio:
            continue
        pi = 0
        j = i
        matched = 0
        while pi < len(prop_lines) and j < len(file_lines):
            if _similar_line(file_lines[j], prop_lines[pi]) >= min_line_ratio:
                matched += 1
                pi += 1
            j += 1
        need = max(2, (len(prop_lines) + 1) // 2)
        if matched >= need and matched > best_score:
            best_score = matched
            best_span = (i, j)
    if best_span is None:
        return None
    lo, hi = best_span
    return "\n".join(file_lines[lo:hi])


def resolve_row_to_verified_snippet(
    row: PatchLocateRow,
    file_content: str,
) -> tuple[str, float] | None:
    """Return ``(verbatim_snippet, confidence)`` if *file_content* contains the snippet."""
    content = _norm_crlf(file_content)
    proposed = _norm_crlf(row.original_snippet or "")
    if proposed.strip() and proposed in content:
        return proposed, 1.0

    for sym in row.anchor_symbols or []:
        block = extract_python_def_block(content, sym.strip())
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
        n = (needle or "").strip()
        if len(n) < 2:
            continue
        nl = n.lower()
        for path, body in sorted(files.items()):
            if nl not in _norm_crlf(body).lower():
                continue
            for i, line in enumerate(_norm_crlf(body).splitlines(), 1):
                if nl in line.lower():
                    key = (path, i)
                    if key in seen:
                        continue
                    seen.add(key)
                    hits.append(f"{path}:{i}: {line.strip()[:240]}")
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
            str(finding.get(k) or "") for k in ("title", "description", "fix")
        )
        for m in re.finditer(r"(?:GET|POST|PUT|PATCH|DELETE|HEAD)\s+(/\S+)", blob, re.I):
            needles.append(m.group(0).strip())
        for m in re.finditer(r"['\"](/[a-zA-Z0-9_\-/{}\.]+)['\"]", blob):
            needles.append(m.group(1))
        for m in re.finditer(r"\b(def|async def)\s+([a-zA-Z_][a-zA-Z0-9_]*)\b", blob):
            needles.append(m.group(2))
    seen: set[str] = set()
    out: list[str] = []
    for n in needles:
        s = n.strip()
        if len(s) < 2 or s.lower() in seen:
            continue
        seen.add(s.lower())
        out.append(s)
        if len(out) >= 48:
            break
    return out
