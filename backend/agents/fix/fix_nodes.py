"""LangGraph node implementations for the fix pipeline.

Topology (see :mod:`fix_graph`):

1. :func:`load_context_node` — load scan + files from stores (no LLM).
2. :func:`plan_fixes_node` — structured LLM plan of :class:`FixGroup` batches.
3. :func:`generate_patches_node` — per-group two-step LLM; groups run concurrently
   (capped, see ``FIX_MAX_CONCURRENT_PATCH_GROUPS``) via :mod:`fix_group_run`.
4. :func:`review_patches_node` — optional review of generated diffs.

Target resolution, plan coercion, and patch merge logic live in
:mod:`fix_plan_helpers` and :mod:`fix_patch_helpers`; per-group execution in
:mod:`fix_group_run`.
"""

from __future__ import annotations

import asyncio
from typing import Any

from agents.llm import get_llm
from agents.runtime_log import emit
from core.config import (
    FIX_MAX_CONCURRENT_PATCH_GROUPS,
    FIX_PLAN_MAX_FINDINGS_PER_GROUP,
    FIX_PLAN_MAX_TOKENS,
    FIX_REVIEW_MAX_TOKENS,
)
from core import scan_store as scan_store
from core.finding_files import merge_scan_files_for_fix
from core.finding_files import resolve_path_to_canonical_key, resolve_paths_for_findings

from .fix_plan_helpers import (
    coerce_findings_into_groups,
    ensure_fix_group_metadata,
    plan_needs_coercion,
    rewrite_plan_target_files,
    slugify_title_for_group_id,
)
from .fix_group_run import run_single_group_patches
from .fix_patch_helpers import batch_has_substantive_patches
from .fix_state import (
    FixGroup,
    FixPlan,
    PatchReview,
)
from agents.prompts.fix_prompts import (
    FIX_PLAN_RESOLVED_PATHS_HEADER,
    PLAN_SYSTEM as _PLAN_SYSTEM,
    REVIEW_SYSTEM as _REVIEW_SYSTEM,
    format_fix_plan_user,
    format_patch_review_section_diff,
    format_patch_review_section_no_patches,
    format_patch_review_user,
)

# Node 1: load_context 


def load_context_node(state: dict[str, Any]) -> dict[str, Any]:
    """Bind scan results and the merged file snapshot into fix state. No LLM."""
    fix_id = state.get("fix_id", "")
    scan_id = state.get("scan_id", "")
    emit(fix_id, "info", "Loading scan context for fix session", branch="fix")

    scan = scan_store.get_scan(scan_id)
    if scan is None:
        emit(fix_id, "error", f"Scan {scan_id} not found", branch="fix")
        return {
            "findings": [],
            "files": {},
            "repo_profile": {},
            "target": "unknown",
        }

    from core import fix_store as fix_store

    fix_session = fix_store.get_fix_session(fix_id) or {}
    selected_indices = fix_session.get("finding_indices", [])
    all_findings = scan.get("findings", [])
    if selected_indices:
        findings = [all_findings[i] for i in selected_indices if i < len(all_findings)]
    else:
        findings = all_findings

    files = merge_scan_files_for_fix(fix_session, scan)
    keys_preview = list(files.keys())[:5]
    emit(
        fix_id,
        "info",
        f"Loaded {len(findings)} findings from scan {scan_id}",
        branch="fix",
    )
    emit(
        fix_id,
        "info",
        f"Fix context: {len(files)} source file(s) "
        f"(merged full repo + finding_files bundle)"
        + (f"; sample keys: {keys_preview}" if keys_preview else ""),
        branch="fix",
    )
    if not files:
        emit(
            fix_id,
            "warn",
            "No source files in fix context — patch generation will not have file bodies.",
            branch="fix",
        )

    return {
        "findings": findings,
        "files": files,
        "repo_profile": scan.get("repo_profile", {}),
        "target": scan.get("target", "the repository"),
    }


# Node 2: plan_fixes 


async def plan_fixes_node(state: dict[str, Any]) -> dict[str, Any]:
    """Call the planner LLM, optionally coerce the plan, then normalize ``target_files``."""
    fix_id = state.get("fix_id", "")
    findings = state.get("findings", [])

    if not findings:
        emit(fix_id, "warn", "No findings to fix", branch="fix")
        return {
            "fix_plan": FixPlan(
                groups=[],
                execution_order=[],
                notes="No findings selected.",
            ).model_dump()
        }

    emit(
        fix_id,
        "branch_start",
        f"Planning fixes for {len(findings)} findings",
        branch="fix-planner",
    )

    finding_lines: list[str] = []
    for index, finding in enumerate(findings):
        finding_lines.append(
            f"[{index}] ({finding.get('severity', '?')}) {finding.get('title', '?')} "
            f"@ {finding.get('location', '?')}\n"
            f"    fix: {(finding.get('fix', '') or '')[:200]}"
        )

    files = state.get("files", {})
    file_list = "\n".join(
        f"  - {path} ({len(content)} bytes)" for path, content in files.items()
    )
    resolved_lines = resolve_paths_for_findings(findings, files)
    resolved_block = ""
    if resolved_lines:
        resolved_block = FIX_PLAN_RESOLVED_PATHS_HEADER + "\n".join(
            f"  - {line}" for line in resolved_lines
        )

    user_message = format_fix_plan_user(
        str(state.get("target", "?")),
        "\n".join(finding_lines),
        len(findings),
        len(files),
        file_list,
        resolved_block,
    )

    try:
        llm = get_llm(max_tokens=FIX_PLAN_MAX_TOKENS)
        structured = llm.with_structured_output(FixPlan)
        plan: FixPlan = await asyncio.to_thread(
            structured.invoke,
            [
                {"role": "system", "content": _PLAN_SYSTEM},
                {"role": "user", "content": user_message},
            ],
        )
    except Exception as exc:  # noqa: BLE001
        emit(fix_id, "error", f"Fix planning failed: {exc!s:.140}", branch="fix-planner")
        fallback_groups: list[FixGroup] = []
        used_fallback_ids: set[str] = set()
        for index, finding in enumerate(findings):
            resolved_key = resolve_path_to_canonical_key(finding.get("location", ""), files)
            raw_path = (finding.get("location", "") or "").split(":")[0].strip()
            target_files = [resolved_key] if resolved_key else ([raw_path] if raw_path else [])
            title = str(finding.get("title") or f"Finding {index}").strip()
            base_gid = slugify_title_for_group_id(title, index)
            gid = base_gid
            dup = 1
            while gid in used_fallback_ids:
                gid = f"{base_gid}-d{dup}"
                dup += 1
            used_fallback_ids.add(gid)
            fallback_groups.append(
                FixGroup(
                    group_id=gid,
                    label=title[:220],
                    finding_indices=[index],
                    target_files=target_files,
                    risk_level="medium",
                    commit_message=f"fix: {title[:50]}",
                )
            )
        plan = FixPlan(
            groups=fallback_groups,
            execution_order=[group.group_id for group in fallback_groups],
            notes="Fallback plan — LLM planning failed, one group per finding.",
        )

    plan_dict = plan.model_dump()
    if plan_needs_coercion(
        plan_dict.get("groups") or [],
        findings,
        files,
        FIX_PLAN_MAX_FINDINGS_PER_GROUP,
    ):
        group_count_before = len(plan_dict.get("groups") or [])
        plan_dict["groups"] = coerce_findings_into_groups(
            findings, files, FIX_PLAN_MAX_FINDINGS_PER_GROUP
        )
        plan_dict["execution_order"] = [
            item["group_id"] for item in plan_dict["groups"] if item.get("group_id")
        ]
        coerced_note = (
            f"Server coerced the LLM plan ({group_count_before} -> {len(plan_dict['groups'])} groups): "
            f"max {FIX_PLAN_MAX_FINDINGS_PER_GROUP} findings per group, "
            f"dependency manifests not mixed with code, every finding included."
        )
        previous_notes = (plan_dict.get("notes") or "").strip()
        plan_dict["notes"] = (
            f"{previous_notes}\n{coerced_note}".strip() if previous_notes else coerced_note
        )
        emit(fix_id, "info", coerced_note, branch="fix-planner")
    rewrite_plan_target_files(plan_dict["groups"], findings, files)
    ensure_fix_group_metadata(plan_dict["groups"], findings)
    group_ids = [
        str(item["group_id"])
        for item in plan_dict["groups"]
        if isinstance(item, dict) and item.get("group_id")
    ]
    prev_order = [
        str(x) for x in (plan_dict.get("execution_order") or []) if isinstance(x, str)
    ]
    seen: set[str] = set()
    merged_order: list[str] = []
    for gid in prev_order:
        if gid in group_ids and gid not in seen:
            merged_order.append(gid)
            seen.add(gid)
    for gid in group_ids:
        if gid not in seen:
            merged_order.append(gid)
            seen.add(gid)
    plan_dict["execution_order"] = merged_order

    emit(
        fix_id,
        "branch_done",
        f"Fix plan: {len(plan_dict['groups'])} groups, "
        f"order: {plan_dict.get('execution_order', [])}",
        branch="fix-planner",
    )

    return {"fix_plan": plan_dict}


# Node 3: generate_patches 


async def generate_patches_node(state: dict[str, Any]) -> dict[str, Any]:
    """Run locate+edit for each :class:`FixGroup`; groups execute concurrently up to a cap."""
    fix_id = state.get("fix_id", "")
    fix_plan = state.get("fix_plan", {})
    groups = fix_plan.get("groups", [])
    execution_order = fix_plan.get("execution_order", [])
    findings = state.get("findings", [])
    files = state.get("files", {})

    if not groups:
        emit(fix_id, "warn", "No fix groups to process", branch="fix")
        return {"patch_results": []}

    group_by_id = {item["group_id"]: item for item in groups}
    ordered_groups: list[dict] = []
    for gid in execution_order:
        if gid in group_by_id:
            ordered_groups.append(group_by_id.pop(gid))
    ordered_groups.extend(group_by_id.values())

    from core import fix_store as fix_store

    fix_session = fix_store.get_fix_session(fix_id) or {}
    report_full_list = list(fix_session.get("report_findings_full") or [])

    concurrency = max(1, FIX_MAX_CONCURRENT_PATCH_GROUPS)
    if len(ordered_groups) > 1 and concurrency > 1:
        emit(
            fix_id,
            "info",
            f"Patch generation: {len(ordered_groups)} group(s), up to {concurrency} concurrent",
            branch="fix",
        )

    semaphore = asyncio.Semaphore(concurrency)

    async def _run_group(
        order_index: int,
        group: dict[str, Any],
    ) -> tuple[int, dict[str, Any]]:
        async with semaphore:
            payload = await run_single_group_patches(
                fix_id, group, findings, files, fix_session, report_full_list
            )
            return order_index, payload

    patch_tasks = [
        _run_group(order_index, group)
        for order_index, group in enumerate(ordered_groups)
    ]
    gathered = await asyncio.gather(*patch_tasks)
    gathered.sort(key=lambda item: item[0])
    all_results = [item[1] for item in gathered]

    return {"patch_results": all_results}


# Node 4: review_patches 


async def review_patches_node(state: dict[str, Any]) -> dict[str, Any]:
    """Optional structured review over all per-group patch results."""
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
        fix_id,
        "branch_start",
        f"Reviewing {len(patch_results)} patch group(s)",
        branch="fix-reviewer",
    )

    review_sections: list[str] = []
    for patch_result in patch_results:
        group_heading = (patch_result.get("group_label") or "").strip() or patch_result.get(
            "group_id", "?"
        )
        patches = patch_result.get("patches", [])
        if not patches:
            review_sections.append(
                format_patch_review_section_no_patches(
                    group_heading, str(patch_result.get("notes", "n/a"))
                )
            )
            continue
        for patch in patches:
            diff_text = patch.get("diff", "") or "(no diff)"
            review_sections.append(
                format_patch_review_section_diff(
                    group_heading,
                    str(patch.get("path", "?")),
                    diff_text,
                    str(patch.get("explanation", "n/a")),
                )
            )

    if not review_sections:
        return {
            "review_result": PatchReview(
                approved=True,
                notes="No actual diffs to review — all groups may have failed.",
            ).model_dump()
        }

    user_message = format_patch_review_user(review_sections, len(patch_results))

    try:
        llm = get_llm(max_tokens=FIX_REVIEW_MAX_TOKENS)
        structured = llm.with_structured_output(PatchReview)
        emit(
            fix_id,
            "info",
            "Calling model for patch review…",
            branch="fix-reviewer",
        )
        review: PatchReview = await asyncio.to_thread(
            structured.invoke,
            [
                {"role": "system", "content": _REVIEW_SYSTEM},
                {"role": "user", "content": user_message},
            ],
        )
    except Exception as exc:  
        emit(fix_id, "warn", f"Patch review failed: {exc!s:.140}", branch="fix-reviewer")
        review = PatchReview(
            approved=True,
            warnings=[f"Automated review failed ({exc!s:.100}); manual review recommended."],
            notes="Review LLM call failed — approving with warning.",
        )

    review_dict = review.model_dump()
    sanity_bullets: list[str] = []
    for pr in patch_results:
        heading = (pr.get("group_label") or "").strip() or str(pr.get("group_id", ""))
        for p in pr.get("patches") or []:
            if not isinstance(p, dict):
                continue
            for w in p.get("sanity_warnings") or []:
                sanity_bullets.append(f"[{heading}] {p.get('path')}: {w}")
    if sanity_bullets:
        merged_w = sanity_bullets + list(review_dict.get("warnings") or [])
        review_dict["warnings"] = merged_w

    if review_dict.get("approved") and not batch_has_substantive_patches(patch_results):
        review_dict["approved"] = False
        warning_list = list(review_dict.get("warnings") or [])
        warning_list.append(
            "No substantive diff in any patch — nothing to apply. "
            "Re-run fix mode or select fewer / file-backed findings only."
        )
        review_dict["warnings"] = warning_list
        review_dict["notes"] = (
            (review_dict.get("notes") or "").strip() + " Batch rejected: empty or non-code patches only."
        ).strip()

    status_label = "approved" if review_dict["approved"] else "needs attention"
    emit(
        fix_id,
        "branch_done",
        f"Review complete: {status_label}, {len(review_dict.get('conflicts', []))} conflict(s), "
        f"{len(review_dict.get('warnings', []))} warning(s)",
        branch="fix-reviewer",
    )

    return {"review_result": review_dict}
