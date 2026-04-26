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
    for pr in patch_results:
        for p in pr.get("patches") or []:
            if not isinstance(p, dict):
                continue
            if not patch_dict_is_code_substantive(p):
                continue
            path_key = str(p.get("path") or "")
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
        for pr in patch_results:
            tt = (pr.get("tests_touched") or "").strip().lower()
            if tt and tt not in ("none", "n/a", "not applicable", "n/a."):
                tests_ok = True
                break
        if not tests_ok:
            violations.append(
                "Substantive code patches require a tests_touched line naming tests or "
                "policy assertions (not 'none'). Manifest-only bumps are exempt."
            )

    for pr in patch_results:
        patches = pr.get("patches") or []
        if patches:
            continue
        notes = (pr.get("notes") or "").lower()
        ev = (pr.get("search_evidence") or "").strip()
        if not any(phrase in notes for phrase in REFUSAL_PHRASES):
            continue
        if not ev:
            gid = pr.get("group_id", "?")
            violations.append(
                f"Group {gid}: refusal-style notes without repo-wide search_evidence."
            )

    return violations
