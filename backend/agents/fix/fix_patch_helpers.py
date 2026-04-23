"""Fix patch pipeline helpers: build prompts for the locate/edit LLM steps, verify
verbatim snippets against repo files, merge structured edits into :class:`FilePatch`
rows, and heuristics to reject truncated model output.

Used only by :mod:`fix_nodes.generate_patches` and :mod:`fix_nodes.review_patches`.
"""

from __future__ import annotations

import difflib
from typing import Any

from core.config import FIX_PATCH_GROUP_CONTEXT_MAX_CHARS
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
    """Unified diff between two string snippets (not whole-file)."""
    original_lines = original.splitlines(keepends=True)
    patched_lines = patched.splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(
            original_lines,
            patched_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm="",
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


def patch_dict_is_substantive(patch: dict) -> bool:
    """True when both snippets exist and differ (ignore model-written diff field)."""
    original = (patch.get("original_snippet") or "").strip()
    patched = (patch.get("patched_snippet") or "").strip()
    return bool(original and patched and original != patched)


def batch_has_substantive_patches(patch_results: list[dict]) -> bool:
    for patch_result in patch_results:
        for patch in patch_result.get("patches") or []:
            if isinstance(patch, dict) and patch_dict_is_substantive(patch):
                return True
    return False


def validated_locate_items(
    items: list[PatchLocateRow],
    files: dict[str, str],
    fallback_path: str,
) -> list[tuple[str, str]]:
    """(canonical path, original_snippet) pairs where the snippet is verbatim in the file."""
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in items:
        path = (row.path or "").strip() or fallback_path
        matched_key, file_content = find_file_content(path, files)
        original = row.original_snippet or ""
        if not file_content or not original.strip():
            continue
        if not original_snippet_in_file(original, file_content):
            continue
        dedup_key = (matched_key or path, original)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        out.append((matched_key or path, original))
    return out


def merge_edits_to_file_patches(
    validated_locate_pairs: list[tuple[str, str]],
    edits: list[PatchEditRow],
    files: dict[str, str],
) -> tuple[list[FilePatch], bool, bool]:
    """Join step-2 ``edits`` to validated locate rows. Returns (patches, had_trunc, had_missing_idx)."""
    edits_by_index: dict[int, PatchEditRow] = {edit.index: edit for edit in edits}
    file_patches: list[FilePatch] = []
    had_truncation_reject = False
    had_missing_edit_index = False
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
        _, file_content = find_file_content(path, files)
        if not file_content or not original_snippet_in_file(original_snippet, file_content):
            continue
        file_patches.append(
            FilePatch(
                path=path,
                original_snippet=original_snippet,
                patched_snippet=patched,
                diff=make_unified_diff_snippets(path, original_snippet, patched),
                explanation=edit_row.explanation or "",
            ),
        )
    return file_patches, had_truncation_reject, had_missing_edit_index
