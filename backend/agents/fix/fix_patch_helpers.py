"""Fix patch pipeline helpers: build prompts for the locate/edit LLM steps, verify
verbatim snippets against repo files, merge structured edits into :class:`FilePatch`
rows, and heuristics to reject truncated model output.

Used only by :mod:`fix_nodes.generate_patches` and :mod:`fix_nodes.review_patches`.
"""

from __future__ import annotations

import difflib
import re
from typing import Any

from core.config import (
    FIX_PATCH_GROUP_CONTEXT_MAX_CHARS,
    FIX_PATCH_VERIFY_PYTHON_COMPILE,
    FIX_PROMPT_NARROW_TO_CITED,
)
from core.finding_files import (
    find_file_content,
    infer_paths_from_finding_text,
    parse_line_number_from_location,
    resolve_path_to_canonical_key,
)

from agents.prompts.fix_prompts import (
    PATCH_DOC_ONLY_FINDINGS_INTRO,
    format_fix_group_report_context,
    format_patch_finding_row_doc_only,
    format_patch_finding_row_primary,
)

from .fix_locate import resolve_row_to_verified_snippet
from .fix_plan_helpers import is_manifest_file_key
from .fix_state import FilePatch, PatchEditRow, PatchLocateRow


_SEVERITY_MEDIUM_OR_HIGHER = frozenset({"medium", "high", "critical"})


def report_index_for_finding_in_report(finding: dict, report_full: list[dict]) -> str:
    """Match a finding to the report list index for cross-links in prompts."""
    for report_index, report_item in enumerate(report_full):
        if not isinstance(report_item, dict):
            continue
        if (
            finding.get("title") == report_item.get("title")
            and finding.get("location") == report_item.get("location")
        ):
            return str(report_index)
    return "?"


def format_findings_for_patch_prompt(
    primary_findings: list[dict],
    doc_only_findings: list[dict],
    report_full: list[dict] | None = None,
) -> str:
    """Separate repo-backed findings from doc-only noise for the patch model."""
    report = report_full or []
    chunks: list[str] = []
    if primary_findings:
        chunks.append(
            "\n".join(
                format_patch_finding_row_primary(
                    report_index_for_finding_in_report(finding, report),
                    str(finding.get("severity", "?")),
                    str(finding.get("title", "?")),
                    str(finding.get("location", "?")),
                    finding.get("description", "") or "",
                    finding.get("fix", "") or "",
                )
                for finding in primary_findings
            )
        )
    if doc_only_findings:
        chunks.append(
            PATCH_DOC_ONLY_FINDINGS_INTRO
            + "\n".join(
                format_patch_finding_row_doc_only(
                    report_index_for_finding_in_report(finding, report),
                    str(finding.get("severity", "?")),
                    str(finding.get("title", "?")),
                    str(finding.get("location", "?")),
                )
                for finding in doc_only_findings
            )
        )
    return "\n\n".join(chunks) if chunks else "(no findings)"


def format_group_report_context(
    session: dict[str, Any],
    group_findings: list[dict],
    report_full: list[dict],
    max_chars: int = FIX_PATCH_GROUP_CONTEXT_MAX_CHARS,
) -> str:
    """Compact audit bullets for this FixGroup only (saves tokens vs full report)."""
    report = report_full or []
    bullet_lines: list[str] = []
    for finding in group_findings:
        if not isinstance(finding, dict):
            continue
        report_num = report_index_for_finding_in_report(finding, report)
        bullet_lines.append(
            f"- [report #{report_num}] ({finding.get('severity', '?')}) "
            f"{finding.get('title', '?')} @ {finding.get('location', '?')}"
        )
        description = (finding.get("description") or "").strip()
        if description:
            bullet_lines.append(f"  Detail: {description[:480]}")
        remediation = (finding.get("fix") or "").strip()
        if remediation:
            bullet_lines.append(f"  Remediation: {remediation[:720]}")
    return format_fix_group_report_context(
        str(session.get("report_grade", "?")),
        str(session.get("report_overall_risk", "")),
        len(group_findings),
        bullet_lines,
        max_chars,
    )


def should_narrow_excerpt_for_fix(
    matched_path: str,
    content: str,
    group_findings: list[dict],
    files: dict[str, str],
) -> bool:
    """Narrow to cited line window only for large files that cite explicit lines."""
    if not FIX_PROMPT_NARROW_TO_CITED:
        return False
    if len(content) <= 8_000:
        return False
    for finding in group_findings:
        if not isinstance(finding, dict):
            continue
        if resolve_path_to_canonical_key(finding.get("location", ""), files) != matched_path:
            continue
        if parse_line_number_from_location(finding.get("location", "")) is not None:
            return True
    return False


def file_has_medium_plus_finding(
    matched_path: str,
    excerpt_findings: list[dict],
    files: dict[str, str],
) -> bool:
    """If a medium+ finding targets this file, prefer including the full ingested file in the prompt."""
    for finding in excerpt_findings:
        if str(finding.get("severity") or "").lower() not in _SEVERITY_MEDIUM_OR_HIGHER:
            continue
        key = resolve_path_to_canonical_key(finding.get("location", ""), files)
        if key == matched_path:
            return True
        for inferred in infer_paths_from_finding_text([finding], files):
            if inferred == matched_path:
                return True
    return False


def finding_touches_target_files(
    finding: dict,
    target_keys: list[str],
    files: dict[str, str],
) -> bool:
    """True if the finding maps to a path that this group is loading for patching."""
    if not target_keys:
        return False
    key_set = set(target_keys)
    resolved = resolve_path_to_canonical_key(finding.get("location", ""), files)
    if resolved in key_set:
        return True
    for inferred in infer_paths_from_finding_text([finding], files):
        if inferred in key_set:
            return True
    return False


# Snippet / diff validation 


def original_snippet_in_file(original: str, content: str) -> bool:
    """True if ``original`` is a substring of ``content`` (CRLF normalized)."""
    if not (original or "").strip():
        return False
    if original in content:
        return True
    normalized_orig = original.replace("\r\n", "\n")
    normalized_content = (content or "").replace("\r\n", "\n")
    return normalized_orig in normalized_content


def make_unified_diff_snippets(file_path: str, original: str, patched: str) -> str:
    """Unified diff between two string snippets (not whole-file).

    ``lineterm`` must be ``\\n`` so each hunk line is separated; ``""`` glues the
    whole diff into one string and breaks frontends that split on newlines.
    """
    original_lines = original.splitlines(keepends=True)
    patched_lines = patched.splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(
            original_lines,
            patched_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm="\n",
        )
    )


def _naive_brace_depth(text: str) -> int:
    depth = 0
    for char in text:
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
    return depth


def _naive_paren_depth(text: str) -> int:
    depth = 0
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
    return depth


def _last_non_empty_line(text: str) -> str:
    for line in reversed(text.splitlines()):
        if line.strip():
            return line.rstrip()
    return ""


def patched_snippet_looks_like_diff_garbage(text: str) -> bool:
    """True if the model pasted unified-diff markers or merged +/- lines into *source*."""
    blob = text or ""
    # Merged pins: ``requests==2.32.5+requests==2.32.3`` (not PEP 440 local versions)
    if re.search(r"==[^+\n#]+\+[a-zA-Z_][a-zA-Z0-9_.-]*\s*==", blob):
        return True
    for raw in blob.splitlines():
        line = raw.rstrip("\n")
        stripped = line.lstrip()
        if not stripped:
            continue
        if stripped.startswith(("+++ ", "--- ", "@@")):
            return True
        # Diff added/removed line markers masquerading as Python
        if stripped.startswith(("+def ", "+class ", "+async def ")):
            return True
        if stripped.startswith(("-def ", "-class ", "-async def ")):
            return True
        # Merged hunk (e.g. ``-def get_+def get_user_route...``)
        if stripped.startswith("-") and (
            "+def " in line or "+class " in line or "+async def " in line
        ):
            return True
    return False


_REQ_PIN_EQ = re.compile(
    r"^\s*([a-zA-Z0-9_.\[\]-]+)\s*==\s*([^\s#;]+)\s*(?:#.*)?$",
)


def _pins_eq_map(block: str) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in (block or "").splitlines():
        pin_match = _REQ_PIN_EQ.match(line)
        if pin_match:
            pins[pin_match.group(1).lower().replace("_", "-")] = pin_match.group(2).strip()
    return pins


def _loose_version_tuple(version: str) -> tuple[int | str, ...]:
    """Sortable-ish version for ``==`` pins (no packaging dependency)."""
    v = (version or "").split("+")[0].strip()
    v = re.sub(r"^[vV]", "", v)
    out: list[int | str] = []
    for part in re.split(r"(\d+)", v):
        if not part:
            continue
        if part.isdigit():
            out.append(int(part))
        elif part.strip("."):
            out.append(part.strip("."))
    return tuple(out)


def manifest_pin_is_downgrade(path: str, original: str, patched: str) -> bool:
    """Block ``pkg==older`` when the locate span included ``pkg==newer`` (CVE noise)."""
    if not is_manifest_file_key(path):
        return False
    orig_pins = _pins_eq_map(original)
    new_pins = _pins_eq_map(patched)
    for pkg, old_ver in orig_pins.items():
        if pkg not in new_pins:
            continue
        new_ver = new_pins[pkg]
        if _loose_version_tuple(new_ver) < _loose_version_tuple(old_ver):
            return True
    return False


def replacement_compiles_as_python_module(path: str, file_content: str, original: str, patched: str) -> bool:
    """After replacing the first occurrence of *original*, the full file must compile.

    Multiple occurrences of *original* are allowed (first match is replaced); callers
    should warn. ``count == 0`` still fails.
    """
    if not (path or "").endswith(".py"):
        return True
    if not original or file_content.count(original) < 1:
        return False
    if not FIX_PATCH_VERIFY_PYTHON_COMPILE:
        return True
    new_src = file_content.replace(original, patched, 1)
    try:
        compile(new_src, path, "exec", dont_inherit=True)
    except SyntaxError:
        return False
    return True


def patch_looks_incomplete_or_truncated(patch: dict) -> bool:
    """Heuristic: reject obvious truncation / unbalanced delimiters in ``patched_snippet``."""
    patched = (patch.get("patched_snippet") or "").strip()
    if not patched:
        return True
    if _naive_brace_depth(patched) != 0:
        return True
    if _naive_paren_depth(patched) != 0:
        return True
    last = _last_non_empty_line(patched)
    if last.endswith("\\"):
        return True
    if last.count('"') % 2 == 1 or last.count("'") % 2 == 1:
        return True
    return False


def _py_line_starts_with(text: str, kind: str) -> int:
    """Count logical ``return`` / ``raise`` lines (Python-ish heuristic)."""
    count = 0
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if kind == "return" and (stripped.startswith("return ") or stripped == "return"):
            count += 1
        elif kind == "raise" and stripped.startswith("raise "):
            count += 1
    return count


def patch_fails_sanity_gate(original: str, patched: str) -> bool:
    """True if the edit likely drops error handling or returns (unsafe to apply)."""
    original_text, patched_text = original or "", patched or ""
    orig_return_count = _py_line_starts_with(original_text, "return")
    patched_return_count = _py_line_starts_with(patched_text, "return")
    orig_raise_count = _py_line_starts_with(original_text, "raise")
    patched_raise_count = _py_line_starts_with(patched_text, "raise")
    if orig_return_count >= 1 and patched_return_count < orig_return_count:
        if patched_raise_count < orig_raise_count:
            return True
        if "HTTPException" in original_text and "HTTPException" not in patched_text:
            return True
    if (
        "HTTPException" in original_text
        and "HTTPException" not in patched_text
        and patched_raise_count < orig_raise_count
    ):
        return True
    return False


def _patch_adds_security_controls(patched: str) -> bool:
    """Heuristic: authz / HTTP error paths / current user checks (reduces bogus warnings)."""
    patched_lower = (patched or "").lower()
    needles = (
        "get_current_user",
        "current_user",
        "httpexception",
        "oauth2",
        "security(",
        "depends(",
        " status_code=",
        "403",
        "401",
        "access denied",
        "forbidden",
        "not authorized",
        "content-security-policy",
        "csp",
    )
    return any(needle in patched_lower for needle in needles)


def patch_sanity_warnings(original: str, patched: str) -> list[str]:
    """Non-fatal hints when the patch is kept (gate passed)."""
    if patch_fails_sanity_gate(original, patched):
        return []
    uplift = _patch_adds_security_controls(patched)
    w: list[str] = []
    original_text, patched_text = original or "", patched or ""
    if _py_line_starts_with(original_text, "raise") > _py_line_starts_with(
        patched_text, "raise"
    ):
        if not uplift:
            w.append("Fewer raise statements than before — verify error handling.")
    return_drop = _py_line_starts_with(original_text, "return") - _py_line_starts_with(
        patched_text, "return"
    )
    if not uplift:
        if return_drop >= 2:
            w.append("Several return statements removed — verify all paths still return.")
        elif return_drop == 1 and _py_line_starts_with(original_text, "raise") > _py_line_starts_with(
            patched_text, "raise"
        ):
            w.append("Fewer return and raise statements — verify control flow and errors.")
    if "HTTPException" in original_text and "HTTPException" not in patched_text:
        w.append("HTTPException references removed — ensure API errors are still explicit.")
    return w


def patch_dict_is_substantive(patch: dict) -> bool:
    """True when both snippets exist and differ (ignore model-written diff field)."""
    original = (patch.get("original_snippet") or "").strip()
    patched = (patch.get("patched_snippet") or "").strip()
    return bool(original and patched and original != patched)


def _py_snippet_diff_is_comment_lines_only(original: str, patched: str) -> bool:
    original_lines, patched_lines = original.splitlines(), patched.splitlines()
    if len(original_lines) != len(patched_lines):
        return False
    any_diff = False
    for original_line, patched_line in zip(original_lines, patched_lines):
        if original_line == patched_line:
            continue
        any_diff = True
        if not (
            original_line.lstrip().startswith("#") and patched_line.lstrip().startswith("#")
        ):
            return False
    return any_diff


def _c_js_snippet_diff_is_comment_lines_only(original: str, patched: str) -> bool:
    def is_full_line_comment(line: str) -> bool:
        s = line.strip()
        if not s:
            return True
        if s.startswith("//"):
            return True
        if s.startswith("/*") or s.startswith("*") or s.startswith("*/"):
            return True
        return False

    original_lines, patched_lines = original.splitlines(), patched.splitlines()
    if len(original_lines) != len(patched_lines):
        return False
    any_diff = False
    for original_line, patched_line in zip(original_lines, patched_lines):
        if original_line == patched_line:
            continue
        any_diff = True
        if not (
            is_full_line_comment(original_line) and is_full_line_comment(patched_line)
        ):
            return False
    return any_diff


def patch_dict_is_comment_only_change(patch: dict) -> bool:
    """True when snippets differ only on full-line comments (no executable / markup change)."""
    if not patch_dict_is_substantive(patch):
        return False
    path = (patch.get("path") or "").lower()
    original = patch.get("original_snippet") or ""
    patched = patch.get("patched_snippet") or ""
    if path.endswith(".py"):
        return _py_snippet_diff_is_comment_lines_only(original, patched)
    if path.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
        return _c_js_snippet_diff_is_comment_lines_only(original, patched)
    return False


def patch_dict_is_code_substantive(patch: dict) -> bool:
    """Substantive for gates / review: excludes comment-only rewording."""
    return patch_dict_is_substantive(patch) and not patch_dict_is_comment_only_change(patch)


def batch_has_substantive_patches(patch_results: list[dict]) -> bool:
    for patch_result in patch_results:
        for patch in patch_result.get("patches") or []:
            if isinstance(patch, dict) and patch_dict_is_code_substantive(patch):
                return True
    return False


def resolve_locate_items(
    items: list[PatchLocateRow],
    files: dict[str, str],
    fallback_path: str,
) -> tuple[list[tuple[str, str]], list[float]]:
    """Map locate rows to ``(path, verified_snippet)`` pairs present in repo files.

    Uses verbatim match first, then ``anchor_symbols`` / ``anchor_route`` /
    fuzzy line alignment (:mod:`fix_locate`). Returns parallel confidence scores
    (0–1) for template / gate logic.
    """
    out: list[tuple[str, str]] = []
    confidences: list[float] = []
    seen: set[tuple[str, str]] = set()
    for row in items:
        path = (row.path or "").strip() or fallback_path
        matched_key, file_content = find_file_content(path, files)
        if not file_content:
            continue
        resolved = resolve_row_to_verified_snippet(row, file_content)
        if not resolved:
            continue
        verified, resolve_confidence = resolved
        if not original_snippet_in_file(verified, file_content):
            continue
        dedup_key = (matched_key or path, verified)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        out.append((matched_key or path, verified))
        model_confidence = float(row.confidence) if row.confidence is not None else 0.75
        merged_confidence = min(1.0, 0.5 * model_confidence + 0.5 * resolve_confidence)
        confidences.append(merged_confidence)
    return out, confidences


def validated_locate_items(
    items: list[PatchLocateRow],
    files: dict[str, str],
    fallback_path: str,
) -> list[tuple[str, str]]:
    """Backward-compatible: return only pairs (no confidence list)."""
    pairs, _ = resolve_locate_items(items, files, fallback_path)
    return pairs


def merge_edits_to_file_patches(
    validated_locate_pairs: list[tuple[str, str]],
    edits: list[PatchEditRow],
    files: dict[str, str],
) -> tuple[list[FilePatch], bool, bool, bool]:
    """Join step-2 ``edits`` to validated locate rows.

    Returns ``(patches, had_trunc, had_missing_idx, had_sanity_reject)``.
    """
    edits_by_index: dict[int, PatchEditRow] = {edit.index: edit for edit in edits}
    file_patches: list[FilePatch] = []
    had_truncation_reject = False
    had_missing_edit_index = False
    had_sanity_reject = False
    for list_index, (path, original_snippet) in enumerate(validated_locate_pairs):
        if list_index not in edits_by_index:
            had_missing_edit_index = True
            continue
        edit_row = edits_by_index[list_index]
        patched = edit_row.patched_snippet or ""
        if not patched.strip() or original_snippet.strip() == patched.strip():
            continue
        probe = {"original_snippet": original_snippet, "patched_snippet": patched}
        if patch_looks_incomplete_or_truncated(probe):
            had_truncation_reject = True
            continue
        if patched_snippet_looks_like_diff_garbage(patched):
            had_truncation_reject = True
            continue
        if patch_fails_sanity_gate(original_snippet, patched):
            had_sanity_reject = True
            continue
        _, file_content = find_file_content(path, files)
        if not file_content or not original_snippet_in_file(original_snippet, file_content):
            continue
        if manifest_pin_is_downgrade(path, original_snippet, patched):
            had_truncation_reject = True
            continue
        if not replacement_compiles_as_python_module(path, file_content, original_snippet, patched):
            had_truncation_reject = True
            continue
        warnings = list(patch_sanity_warnings(original_snippet, patched))
        match_count = file_content.count(original_snippet)
        if match_count > 1:
            warnings.append(
                f"This snippet matched {match_count} times in the file — only the first was replaced; "
                "verify the correct location."
            )
        file_patches.append(
            FilePatch(
                path=path,
                original_snippet=original_snippet,
                patched_snippet=patched,
                diff=make_unified_diff_snippets(path, original_snippet, patched),
                explanation=edit_row.explanation or "",
                sanity_warnings=warnings,
            ),
        )
    return file_patches, had_truncation_reject, had_missing_edit_index, had_sanity_reject
