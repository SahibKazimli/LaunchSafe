"""Fix graph node implementations.

Four nodes, executed sequentially:

  load_context   — reads scan results + original files (no LLM)
  plan_fixes     — LLM groups findings into logical fix batches
  generate_patches — LLM generates unified-diff patches per group
  review_patches — LLM cross-checks patches for conflicts
"""

from __future__ import annotations

import difflib
from typing import Any

from agents.llm import get_llm
from agents.runtime_log import emit
from core.config import SYNTH_MAX_TOKENS, SPEC_MAX_TOKENS
from core import scan_store as _ss

from .state import (
    FilePatch,
    FixGroup,
    FixPlan,
    PatchResult,
    PatchReview,
)


# Node 1: Load Context   


def load_context_node(state: dict[str, Any]) -> dict[str, Any]:
    """Pull scan results and original files into fix state.

    Pure data wiring — no LLM call.
    """
    fix_id = state.get("fix_id", "")
    scan_id = state.get("scan_id", "")
    emit(fix_id, "info", "Loading scan context for fix session", branch="fix")

    scan = _ss.get_scan(scan_id)
    if scan is None:
        emit(fix_id, "error", f"Scan {scan_id} not found", branch="fix")
        return {
            "findings": [],
            "files": {},
            "repo_profile": {},
            "target": "unknown",
        }

    # Filter to selected finding indices
    all_findings = scan.get("findings", [])
    selected_indices = state.get("_finding_indices", [])
    if selected_indices:
        findings = [
            all_findings[i]
            for i in selected_indices
            if i < len(all_findings)
        ]
    else:
        # Default: all critical + high findings
        findings = [
            finding for finding in all_findings
            if finding.get("severity", "").lower() in ("critical", "high")
        ]

    emit(
        fix_id, "info",
        f"Loaded {len(findings)} findings from scan {scan_id}",
        branch="fix",
    )

    return {
        "findings": findings,
        "files": scan.get("_files", {}),  # stashed during scan
        "repo_profile": scan.get("repo_profile", {}),
        "target": scan.get("target", "the repository"),
    }


# Node 2: Plan Fixes 

_PLAN_SYSTEM = """\
You are a senior security engineer planning a coordinated fix session.
You receive a list of security findings from an audit. Your job is to
group them into logical fix batches that can be applied together.

Rules:
  - Findings in the SAME FILE should be in the same group.
  - Related findings across files (e.g. auth config + auth middleware)
    should be grouped together if they share a logical concern.
  - Order groups by dependency: config/dependency fixes first, then
    code that reads the config.
  - Each group gets a risk_level:
      "low"    — formatting, headers, documentation
      "medium" — logic changes, input validation
      "high"   — auth/payment/crypto/session changes
  - Each group gets a conventional commit message.
  - Keep groups focused. 2-6 findings per group is typical.
    Don't put everything in one mega-group.
"""


async def plan_fixes_node(state: dict[str, Any]) -> dict[str, Any]:
    """LLM groups findings into FixGroup batches."""
    fix_id = state.get("fix_id", "")
    findings = state.get("findings", [])

    if not findings:
        emit(fix_id, "warn", "No findings to fix", branch="fix")
        return {
            "fix_plan": FixPlan(
                groups=[], execution_order=[], notes="No findings selected."
            ).model_dump()
        }

    emit(
        fix_id, "branch_start",
        f"Planning fixes for {len(findings)} findings",
        branch="fix-planner",
    )

    # Build the findings summary for the LLM
    finding_lines = []
    for i, f in enumerate(findings):
        finding_lines.append(
            f"[{i}] ({f.get('severity', '?')}) {f.get('title', '?')} "
            f"@ {f.get('location', '?')}\n"
            f"    fix: {(f.get('fix', '') or '')[:200]}"
        )

    # Also list available files
    files = state.get("files", {})
    file_list = "\n".join(f"  - {p} ({len(c)} bytes)" for p, c in files.items())

    user_msg = (
        f"Target: {state.get('target', '?')}\n\n"
        f"FINDINGS ({len(findings)}):\n"
        + "\n".join(finding_lines)
        + f"\n\nAVAILABLE FILES ({len(files)}):\n{file_list}"
    )

    try:
        llm = get_llm(max_tokens=SYNTH_MAX_TOKENS)
        structured = llm.with_structured_output(FixPlan)
        plan: FixPlan = structured.invoke([
            {"role": "system", "content": _PLAN_SYSTEM},
            {"role": "user", "content": user_msg},
        ])
    except Exception as exc:
        emit(fix_id, "error", f"Fix planning failed: {exc!s:.140}", branch="fix-planner")
        # Fallback: one group per finding
        groups = []
        for i, f in enumerate(findings):
            groups.append(FixGroup(
                group_id=f"fix-{i}",
                label=f.get("title", f"Fix {i}")[:60],
                finding_indices=[i],
                target_files=[f.get("location", "").split(":")[0]],
                risk_level="medium",
                commit_message=f"fix: {f.get('title', 'security fix')[:50]}",
            ))
        plan = FixPlan(
            groups=groups,
            execution_order=[g.group_id for g in groups],
            notes="Fallback plan — LLM planning failed, one group per finding.",
        )

    emit(
        fix_id, "branch_done",
        f"Fix plan: {len(plan.groups)} groups, order: {plan.execution_order}",
        branch="fix-planner",
    )

    return {"fix_plan": plan.model_dump()}


# Node 3: Generate Patches


_PATCH_SYSTEM = """\
You are a senior security engineer applying fixes to production code.
You receive a group of related security findings and the original file
contents. Generate the MINIMAL code change that fixes ALL issues in
this group.

Rules:
  - Preserve ALL existing functionality. Do NOT refactor unrelated code.
  - Preserve all comments and documentation unless they are the bug.
  - For each file you modify, provide:
      1. The original code snippet (the relevant section, with 5-10
         lines of surrounding context)
      2. The patched code snippet (drop-in replacement)
      3. A unified diff
      4. One-sentence explanation of the change
  - If a fix requires adding a new import, include it.
  - If a fix requires adding a dependency, note it in your explanation
    but do NOT modify package.json/requirements.txt unless it's in
    your target files.
  - Generate REAL code that compiles/runs. No pseudocode, no TODOs,
    no "implement this here" placeholders.
"""


def _make_diff(path: str, original: str, patched: str) -> str:
    """Generate unified diff from two code snippets."""
    orig_lines = original.splitlines(keepends=True)
    patch_lines = patched.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines, patch_lines,
        fromfile=f"a/{path}", tofile=f"b/{path}",
        lineterm="",
    )
    return "".join(diff)


async def generate_patches_node(state: dict[str, Any]) -> dict[str, Any]:
    """Generate patches for each fix group sequentially."""
    fix_id = state.get("fix_id", "")
    fix_plan = state.get("fix_plan", {})
    groups = fix_plan.get("groups", [])
    execution_order = fix_plan.get("execution_order", [])
    findings = state.get("findings", [])
    files = state.get("files", {})

    if not groups:
        emit(fix_id, "warn", "No fix groups to process", branch="fix")
        return {"patch_results": []}

    # Order groups by execution_order if available
    group_map = {group["group_id"]: group for group in groups}
    ordered = []
    for group_id in execution_order:
        if group_id in group_map:
            ordered.append(group_map.pop(group_id))
    ordered.extend(group_map.values())  # append any not in order

    all_results: list[dict] = []

    for group in ordered:
        group_id = group["group_id"]
        label = group.get("label", group_id)
        emit(
            fix_id, "branch_start",
            f"Generating patches for: {label}",
            branch=f"fix-{group_id}",
        )

        # Gather the relevant findings
        group_findings = []
        for idx in group.get("finding_indices", []):
            if idx < len(findings):
                group_findings.append(findings[idx])

        # Gather the relevant file contents
        target_files = group.get("target_files", [])
        file_sections = []
        for path in target_files:
            content = files.get(path, "")
            if content:
                # Truncate very large files
                snippet = content[:15_000]
                if len(content) > 15_000:
                    snippet += "\n...[truncated]"
                file_sections.append(f"### {path}\n```\n{snippet}\n```")

        # Build the prompt
        finding_text = "\n".join(
            f"- ({finding.get('severity', '?')}) {finding.get('title', '?')} "
            f"@ {finding.get('location', '?')}\n"
            f"  Description: {(finding.get('description', '') or '')[:200]}\n"
            f"  Suggested fix: {(finding.get('fix', '') or '')[:300]}"
            for finding in group_findings
        )
        files_text = "\n\n".join(file_sections) if file_sections else "(no file content available)"

        user_msg = (
            f"FIX GROUP: {label}\n"
            f"Commit message: {group.get('commit_message', '')}\n"
            f"Risk level: {group.get('risk_level', 'medium')}\n\n"
            f"FINDINGS TO FIX:\n{finding_text}\n\n"
            f"ORIGINAL FILES:\n{files_text}"
        )

        try:
            llm = get_llm(max_tokens=SPEC_MAX_TOKENS)
            structured = llm.with_structured_output(PatchResult)
            result: PatchResult = structured.invoke([
                {"role": "system", "content": _PATCH_SYSTEM},
                {"role": "user", "content": user_msg},
            ])

            # Backfill diffs if the LLM didn't generate them
            for patch in result.patches:
                if not patch.diff and patch.original_snippet and patch.patched_snippet:
                    patch.diff = _make_diff(
                        patch.path,
                        patch.original_snippet,
                        patch.patched_snippet,
                    )

            emit(
                fix_id, "branch_done",
                f"{label}: {len(result.patches)} file(s) patched",
                branch=f"fix-{group_id}",
            )
            all_results.append(result.model_dump())

        except Exception as exc:
            emit(
                fix_id, "warn",
                f"{label} patch generation failed: {exc!s:.140}",
                branch=f"fix-{group_id}",
            )
            all_results.append(PatchResult(
                group_id=group_id,
                patches=[],
                notes=f"Patch generation failed: {exc!s:.200}",
            ).model_dump())

    return {"patch_results": all_results}


# Node 4: Review Patches 


_REVIEW_SYSTEM = """\
You are a senior code reviewer checking a batch of security patches
before they are committed.

Review the patches for:
  1. CONFLICTS: Two patches editing the same lines differently.
  2. REGRESSIONS: A fix that breaks something another patch assumes
     (e.g. renaming a function that another patch calls).
  3. MISSING IMPORTS: A patch uses a symbol not imported.
  4. SYNTAX ERRORS: Obvious syntax problems in the patched code.
  5. INCOMPLETE FIXES: A patch that addresses the symptom but not the
     root cause.

Set approved=true if the patches are safe to apply as a batch.
Set approved=false and explain in conflicts/warnings if not.
"""


async def review_patches_node(state: dict[str, Any]) -> dict[str, Any]:
    """Cross-check all patches for conflicts and regressions."""
    fix_id = state.get("fix_id", "")
    patch_results = state.get("patch_results", [])

    if not patch_results:
        return {
            "review_result": PatchReview(
                approved=True,
                notes="No patches to review.",
            ).model_dump()
        }

    emit(
        fix_id, "branch_start",
        f"Reviewing {len(patch_results)} patch group(s)",
        branch="fix-reviewer",
    )

    # Build review input
    review_sections = []
    for pr in patch_results:
        group_id = pr.get("group_id", "?")
        patches = pr.get("patches", [])
        for p in patches:
            diff = p.get("diff", "") or "(no diff)"
            review_sections.append(
                f"### {group_id} → {p.get('path', '?')}\n"
                f"```diff\n{diff[:3000]}\n```\n"
                f"Explanation: {p.get('explanation', 'n/a')}"
            )

    if not review_sections:
        return {
            "review_result": PatchReview(
                approved=True,
                notes="No actual diffs to review — all groups may have failed.",
            ).model_dump()
        }

    user_msg = (
        f"PATCHES TO REVIEW ({len(review_sections)} files across "
        f"{len(patch_results)} groups):\n\n"
        + "\n\n---\n\n".join(review_sections)
    )

    try:
        llm = get_llm(max_tokens=SYNTH_MAX_TOKENS)
        structured = llm.with_structured_output(PatchReview)
        review: PatchReview = structured.invoke([
            {"role": "system", "content": _REVIEW_SYSTEM},
            {"role": "user", "content": user_msg},
        ])
    except Exception as exc:
        emit(fix_id, "warn", f"Patch review failed: {exc!s:.140}", branch="fix-reviewer")
        review = PatchReview(
            approved=True,
            warnings=[f"Automated review failed ({exc!s:.100}); manual review recommended."],
            notes="Review LLM call failed — approving with warning.",
        )

    status = "approved" if review.approved else "needs attention"
    emit(
        fix_id, "branch_done",
        f"Review complete: {status}, {len(review.conflicts)} conflict(s), "
        f"{len(review.warnings)} warning(s)",
        branch="fix-reviewer",
    )

    return {"review_result": review.model_dump()}
