"""Post-generation quality gates for fix sessions (no-op detection, refusal language)."""

from __future__ import annotations

from typing import Any

from core.finding_files import infer_paths_from_finding_text, resolve_path_to_canonical_key

from .fix_patch_helpers import batch_has_substantive_patches, patch_dict_is_code_substantive
from .fix_plan_helpers import is_manifest_file_key

REFUSAL_PHRASES: tuple[str, ...] = (
    "could not find",
    "not present in",
    "no verbatim",
    "not found in the excerpt",
    "cannot locate",
    "unable to find",
    "does not appear in",
    "not in the provided excerpt",
)


def substantive_touches_non_manifest_code(patch_results: list[dict[str, Any]]) -> bool:
    """True if any substantive patch edits something other than lockfiles/manifests."""
    for patch_result in patch_results:
        for p in patch_result.get("patches") or []:
            if not isinstance(patch, dict):
                continue
            if not patch_dict_is_code_substantive(patch):
                continue
            path_key = str(patch.get("path") or "")
            if is_manifest_file_key(path_key):
                continue
            return True
    return False


def findings_have_repo_backing(findings: list[dict], files: dict[str, str]) -> bool:
    """True if at least one finding maps to an ingested file path."""
    if not findings or not files:
        return False
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if resolve_path_to_canonical_key(finding.get("location", ""), files):
            return True
        if infer_paths_from_finding_text([finding], files, max_paths=4):
            return True
    return False


def evaluate_fix_session_quality(
    findings: list[dict],
    files: dict[str, str],
    patch_results: list[dict[str, Any]],
) -> list[str]:
    """Return human-readable violations; empty list means gates passed."""
    violations: list[str] = []
    if not patch_results:
        if findings_have_repo_backing(findings, files):
            violations.append("No patch groups returned despite file-backed findings.")
        return violations

    substantive = batch_has_substantive_patches(patch_results)
    actionable = findings_have_repo_backing(findings, files)

    if actionable and not substantive:
        violations.append(
            "No substantive code patches were produced for file-backed findings."
        )

    if substantive and substantive_touches_non_manifest_code(patch_results):
        tests_ok = False
        for patch_result in patch_results:
            tests_touched = (patch_result.get("tests_touched") or "").strip().lower()
            if tests_touched and tests_touched not in ("none", "n/a", "not applicable", "n/a."):
                tests_ok = True
                break
        if not tests_ok:
            violations.append(
                "Substantive code patches require a tests_touched line naming tests or "
                "policy assertions (not 'none'). Manifest-only bumps are exempt."
            )

    for patch_result in patch_results:
        patches = patch_result.get("patches") or []
        if patches:
            continue
        notes = (patch_result.get("notes") or "").lower()
        evidence = (patch_result.get("search_evidence") or "").strip()
        if not any(refusal_phrase in notes for refusal_phrase in REFUSAL_PHRASES):
            continue
        if not evidence:
            group_id = patch_result.get("group_id", "?")
            violations.append(
                f"Group {group_id}: refusal-style notes without repo-wide search_evidence."
            )

    return violations
