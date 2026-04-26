"""Fix session orchestrator that drives the fix LangGraph pipeline.
"""

from __future__ import annotations

from agents.runtime_log import emit
from core import fix_store as _fs
from core import scan_store as _ss
from core.finding_files import merge_scan_files_for_fix


async def run_fix_session(
    fix_id: str,
    scan_id: str,
    finding_indices: list[int],
) -> None:
    """Drive the fix graph end-to-end.

    Called as a background task from the ``/start-fix`` route.
    """
    _fs.mark_running(fix_id)
    session = _fs.get_fix_session(fix_id)
    if session is None:
        return

    emit(fix_id, "info", f"Starting fix session for scan {scan_id}", branch="fix")

    # Verify the scan exists and is done
    scan = _ss.get_scan(scan_id)
    if scan is None:
        _fs.update_fix_session(
            fix_id,
            status="error",
            error=f"Scan {scan_id} not found.",
        )
        return

    if scan.get("status") != "done":
        _fs.update_fix_session(
            fix_id,
            status="error",
            error=f"Scan {scan_id} is not complete (status: {scan.get('status')}).",
        )
        return

    files_blob = merge_scan_files_for_fix(session, scan)
    if not files_blob:
        msg = (
            "This scan has no stashed source files (and no finding file bundle). "
            "Re-run the scan, then try fix mode again."
        )
        _fs.update_fix_session(fix_id, status="error", error=msg)
        emit(fix_id, "error", msg, branch="fix")
        return

    try:
        from agents.fix.fix_graph import get_fix_agent

        agent = get_fix_agent()
        result = await agent.ainvoke({
            "scan_id": scan_id,
            "fix_id": fix_id,
            "target": scan.get("target", ""),
            "findings": [],  # populated by load_context
            "files": {},     # populated by load_context
            "repo_profile": {},
            "fix_plan": {},
            "patch_results": [],
            "review_result": {},
            # Private field for load_context to use
            "_finding_indices": finding_indices,
        })

        fix_plan = result.get("fix_plan", {})
        patch_results = result.get("patch_results", [])
        review_result = result.get("review_result", {})
        findings_done = result.get("findings") or []
        files_done = result.get("files") or files_blob

        from agents.fix.fix_validators import evaluate_fix_session_quality

        quality_violations = evaluate_fix_session_quality(
            findings_done,
            files_done,
            patch_results,
        )
        if quality_violations:
            review_merged = dict(review_result) if review_result else {}
            review_merged["approved"] = False
            warn_list = list(review_merged.get("warnings") or [])
            for msg in reversed(quality_violations):
                warn_list.insert(0, f"Quality gate: {msg}")
            review_merged["warnings"] = warn_list
            prev_notes = (review_merged.get("notes") or "").strip()
            gate_blob = " ".join(quality_violations)
            review_merged["notes"] = (
                f"{prev_notes}\n{gate_blob}".strip() if prev_notes else gate_blob
            )
            review_result = review_merged

        _fs.update_fix_session(
            fix_id,
            status="done",
            fix_plan=fix_plan,
            patches=patch_results,
            review=review_result,
            quality_gate_violations=quality_violations,
        )

        total_patches = sum(
            len(group_result.get("patches", []))
            for group_result in patch_results
        )
        emit(
            fix_id, "info",
            f"Fix session complete: {len(patch_results)} group(s), "
            f"{total_patches} file patch(es)",
            branch="fix",
        )

    except Exception as exc:
        error_msg = f"Fix session failed: {exc!s}"[:300]
        _fs.update_fix_session(fix_id, status="error", error=error_msg)
        emit(fix_id, "error", error_msg, branch="fix")
