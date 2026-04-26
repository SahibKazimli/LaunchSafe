"""Single fix-group worker: build prompts, run locate+edit LLMs, return a PatchResult dict.

Invoked concurrently by :func:`fix_nodes.generate_patches_node` (bounded by a semaphore)
so multiple groups can progress at once without blocking the asyncio loop.
"""

from __future__ import annotations

import asyncio
from typing import Any

from agents.llm import get_llm
from agents.runtime_log import emit
from core.config import (
    FIX_GROUP_MAX_FILES,
    FIX_PATCH_FILE_PROMPT_MAX_CHARS,
    FIX_PATCH_LINE_MARGIN,
    FIX_PATCH_LLM_TEMPERATURE,
    FIX_PATCH_MAX_TOKENS,
    FIX_PATCH_REACT_ENABLED,
    FIX_PATCH_REACT_FALLBACK_LEGACY,
    fix_patch_react_recursion_limit,
)
from core.finding_files import build_excerpt_for_fix_prompt, find_file_content

from agents.prompts.fix_prompts import (
    PATCH_BROAD_PATH_HINT,
    PATCH_EDIT_RETRY as _PATCH_EDIT_RETRY,
    PATCH_EDIT_RETRY_2 as _PATCH_EDIT_RETRY_2,
    PATCH_EDIT_RETRY_GROUNDING as _PATCH_EDIT_RETRY_GROUNDING,
    PATCH_EDIT_RETRY_SYNTAX as _PATCH_EDIT_RETRY_SYNTAX,
    PATCH_EDIT_SYSTEM as _PATCH_EDIT_SYSTEM,
    PATCH_LOCATE_RETRY as _PATCH_LOCATE_RETRY,
    PATCH_LOCATE_RETRY_2 as _PATCH_LOCATE_RETRY_2,
    PATCH_LOCATE_SYSTEM as _PATCH_LOCATE_SYSTEM,
    format_patch_edit_user,
    format_patch_edit_user_react,
    format_patch_file_missing_user,
    format_patch_locate_targets_block,
    format_patch_locate_user,
    remediation_templates_for_findings,
)
from .fix_locate import (
    collect_evidence_needles_from_findings,
    repo_wide_search_evidence,
)
from .fix_patch_helpers import (
    file_has_medium_plus_finding,
    finding_touches_target_files,
    format_findings_for_patch_prompt,
    format_group_report_context,
    merge_edits_to_file_patches,
    resolve_locate_items,
    should_narrow_excerpt_for_fix,
)
from .fix_plan_helpers import (
    expand_target_keys_for_group,
    resolve_target_files_for_group,
    supplement_api_like_targets,
)
from .fix_patch_react import (
    REACT_DIAG_RECURSION_LIMIT,
    edits_tool_grounding_ok,
    run_fix_patch_react_edit,
)
from .fix_state import FilePatch, PatchEditBundle, PatchLocateBundle, PatchResult


async def run_single_group_patches(
    fix_id: str,
    group: dict[str, Any],
    findings: list[dict],
    files: dict[str, str],
    fix_session: dict[str, Any],
    report_full_list: list[dict],
) -> dict[str, Any]:
    """Execute the two-step locate+edit pipeline for one ``FixGroup``; return ``PatchResult`` as dict."""
    group_id = group["group_id"]
    label = group.get("label", group_id)
    group_label = str(label)[:300]
    emit(
        fix_id,
        "branch_start",
        f"Generating patches for: {label}",
        branch=f"fix-{group_id}",
    )

    group_findings: list[dict] = []
    for index in group.get("finding_indices", []):
        if index < len(findings):
            group_findings.append(findings[index])

    raw_targets = list(group.get("target_files") or [])
    target_keys = resolve_target_files_for_group(raw_targets, group_findings, files)
    target_keys = expand_target_keys_for_group(
        group_findings, files, target_keys, FIX_GROUP_MAX_FILES
    )
    target_keys = supplement_api_like_targets(
        files, group_findings, target_keys, FIX_GROUP_MAX_FILES
    )

    code_findings = [
        finding
        for finding in group_findings
        if finding_touches_target_files(finding, target_keys, files)
    ]
    doc_only_findings = [finding for finding in group_findings if finding not in code_findings]
    excerpt_findings = code_findings if code_findings else group_findings

    report_context = format_group_report_context(
        fix_session, group_findings, report_full_list
    )

    file_sections: list[str] = []
    missing_paths: list[str] = []
    for path in target_keys:
        matched_path, content = find_file_content(path, files)
        if content:
            cap = FIX_PATCH_FILE_PROMPT_MAX_CHARS
            if file_has_medium_plus_finding(matched_path, excerpt_findings, files):
                cap = min(max(cap, len(content) + 64), FIX_PATCH_FILE_PROMPT_MAX_CHARS)
            file_sections.append(
                build_excerpt_for_fix_prompt(
                    matched_path,
                    content,
                    excerpt_findings,
                    files,
                    full_file_max_chars=cap,
                    line_margin=FIX_PATCH_LINE_MARGIN,
                    narrow_to_cited_region=should_narrow_excerpt_for_fix(
                        matched_path, content, excerpt_findings, files
                    ),
                )
            )
        else:
            missing_paths.append(path)

    if missing_paths:
        emit(
            fix_id,
            "warn",
            f"{group_id}: could not find content for: {', '.join(missing_paths[:5])}",
            branch=f"fix-{group_id}",
        )

    has_file_content = bool(file_sections)

    if code_findings:
        finding_text = format_findings_for_patch_prompt(
            code_findings, doc_only_findings, report_full_list
        )
    else:
        finding_text = format_findings_for_patch_prompt(
            group_findings, [], report_full_list
        )

    if has_file_content:
        files_text = "\n\n".join(file_sections)
    else:
        hint_parts = list(raw_targets) + [
            finding.get("location", "") for finding in group_findings
        ]
        cleaned = {
            hint
            for hint in hint_parts
            if hint and str(hint).strip().lower() not in ("unknown", "?", "n/a")
        }
        missing_list = ", ".join(sorted(cleaned)) if cleaned else (
            "no matching repo path (empty or non-path locations); "
            "narrative text did not match any file key"
        )
        files_text = format_patch_file_missing_user(missing_list)

    broad_path_hint = "" if code_findings else PATCH_BROAD_PATH_HINT

    user_message = format_patch_locate_user(
        report_context,
        str(group.get("label", group_id)),
        str(group.get("commit_message", "")),
        str(group.get("risk_level", "medium")),
        finding_text,
        files_text,
        broad_path_hint,
    )

    if not has_file_content:
        emit(
            fix_id,
            "branch_done",
            f"{label}: skipped (no repo files for this group)",
            branch=f"fix-{group_id}",
        )
        evidence_skipped = repo_wide_search_evidence(
            files,
            collect_evidence_needles_from_findings(group_findings),
        )
        return PatchResult(
            group_id=group_id,
            group_label=group_label,
            patches=[],
            notes=(
                "Skipped: no matching source files in this scan for this group "
                "(docs/policy-only or paths that did not resolve). "
                "Address these findings manually or re-run with paths in locations."
            ),
            search_evidence=evidence_skipped,
        ).model_dump()

    try:
        llm = get_llm(
            max_tokens=FIX_PATCH_MAX_TOKENS,
            temperature=FIX_PATCH_LLM_TEMPERATURE,
        )
        fallback_path = target_keys[0] if target_keys else "file"

        locate_structured = llm.with_structured_output(PatchLocateBundle)
        extra_locate_system = ""
        locate_bundle: PatchLocateBundle | None = None
        validated_pairs: list[tuple[str, str]] = []
        locate_confidences: list[float] = []
        for attempt in range(3):
            locate_system = _PATCH_LOCATE_SYSTEM + extra_locate_system
            if attempt == 2:
                locate_system += _PATCH_LOCATE_RETRY_2
            emit(
                fix_id,
                "info",
                f"{label}: LLM locate step (attempt {attempt + 1}/3)…",
                branch=f"fix-{group_id}",
            )
            locate_bundle = await asyncio.to_thread(
                locate_structured.invoke,
                [
                    {"role": "system", "content": locate_system},
                    {"role": "user", "content": user_message},
                ],
            )
            validated_pairs, locate_confidences = resolve_locate_items(
                locate_bundle.items, files, fallback_path
            )
            if validated_pairs:
                break
            if attempt < 2:
                emit(
                    fix_id,
                    "warn",
                    f"{label}: locate step — no resolvable code regions (retry {attempt + 1}/2)",
                    branch=f"fix-{group_id}",
                )
                extra_locate_system += _PATCH_LOCATE_RETRY

        raw_locate_count = len(locate_bundle.items) if locate_bundle else 0
        emit(
            fix_id,
            "info",
            f"{label}: locate resolved {len(validated_pairs)} verified region(s) "
            f"from {raw_locate_count} locate items",
            branch=f"fix-{group_id}",
        )
        for section in file_sections:
            first_line = (section.split("\n")[0] or "")[:120]
            emit(
                fix_id,
                "info",
                f"{group_id}: file section: {first_line}",
                branch=f"fix-{group_id}",
            )

        file_patches: list[FilePatch] = []
        note_parts: list[str] = []
        had_sanity_reject_any = False
        if locate_bundle:
            note_parts.append((locate_bundle.notes or "").strip())

        evidence_needles = collect_evidence_needles_from_findings(group_findings)
        search_evidence = repo_wide_search_evidence(files, evidence_needles)

        controls_added = ""
        tests_touched = ""
        residual_risk = ""

        if not validated_pairs:
            hint = (
                " Step 1 could not resolve any region to verified code in the repo "
                "(try wider scan file bundle). Repo-wide search evidence is attached."
            )
            merged_notes = f"{' '.join(part for part in note_parts if part)}{hint}".strip()
            if search_evidence:
                merged_notes = f"{merged_notes}\n\nRepo-wide hits:\n{search_evidence}".strip()
        else:
            locate_block = format_patch_locate_targets_block(validated_pairs)
            min_conf = min(locate_confidences) if locate_confidences else 0.0
            risk = str(group.get("risk_level", "")).lower()
            remediation_block = ""
            if min_conf < 0.95 or risk == "high":
                remediation_block = remediation_templates_for_findings(group_findings)
            edit_user_message = format_patch_edit_user(
                report_context,
                str(group.get("label", group_id)),
                str(group.get("commit_message", "")),
                str(group.get("risk_level", "medium")),
                finding_text,
                len(validated_pairs) - 1,
                locate_block,
                files_text,
                remediation_templates=remediation_block,
            )
            react_user_message = format_patch_edit_user_react(
                report_context,
                str(group.get("label", group_id)),
                str(group.get("commit_message", "")),
                str(group.get("risk_level", "medium")),
                finding_text,
                len(validated_pairs) - 1,
                locate_block,
                remediation_templates=remediation_block,
            )
            edit_structured = llm.with_structured_output(PatchEditBundle)
            extra_edit_system = ""
            edit_bundle: PatchEditBundle | None = None

            if FIX_PATCH_REACT_ENABLED:
                emit(
                    fix_id,
                    "info",
                    f"{label}: ReAct patch step (tool-grounded)…",
                    branch=f"fix-{group_id}",
                )
                edit_bundle, react_keys, react_diag = await run_fix_patch_react_edit(
                    react_user_message,
                    files,
                )
                if react_diag:
                    if react_diag == REACT_DIAG_RECURSION_LIMIT:
                        emit(
                            fix_id,
                            "info",
                            f"{label}: ReAct patch stopped at tool-depth limit "
                            f"(recursion_limit={fix_patch_react_recursion_limit()!r}); "
                            f"continuing with legacy edit if enabled.",
                            branch=f"fix-{group_id}",
                        )
                    else:
                        emit(
                            fix_id,
                            "warn",
                            f"{label}: ReAct patch — {react_diag[:220]}",
                            branch=f"fix-{group_id}",
                        )
                if edit_bundle:
                    g_ok, gmsg = edits_tool_grounding_ok(
                        validated_pairs,
                        edit_bundle.edits,
                        react_keys,
                        files,
                    )
                    if g_ok:
                        file_patches, had_trunc, had_missing, had_sanity = (
                            merge_edits_to_file_patches(
                                validated_pairs,
                                edit_bundle.edits,
                                files,
                            )
                        )
                        if had_sanity:
                            had_sanity_reject_any = True
                            emit(
                                fix_id,
                                "warn",
                                f"{label}: rejected edit(s) — would drop return/raise or HTTPException "
                                f"without equivalent replacement",
                                branch=f"fix-{group_id}",
                            )
                    else:
                        emit(
                            fix_id,
                            "warn",
                            f"{label}: ReAct patch discarded — {gmsg}",
                            branch=f"fix-{group_id}",
                        )
                        note_parts.append(gmsg)
                        edit_bundle = None

            if not file_patches and FIX_PATCH_REACT_FALLBACK_LEGACY:
                if FIX_PATCH_REACT_ENABLED:
                    emit(
                        fix_id,
                        "info",
                        f"{label}: Legacy excerpt-based edit step (fallback)…",
                        branch=f"fix-{group_id}",
                    )
                edit_bundle = None
                for attempt in range(3):
                    edit_system = _PATCH_EDIT_SYSTEM + extra_edit_system
                    if attempt == 2:
                        edit_system += _PATCH_EDIT_RETRY_2
                    emit(
                        fix_id,
                        "info",
                        f"{label}: LLM edit step (attempt {attempt + 1}/3)…",
                        branch=f"fix-{group_id}",
                    )
                    edit_bundle = await asyncio.to_thread(
                        edit_structured.invoke,
                        [
                            {"role": "system", "content": edit_system},
                            {"role": "user", "content": edit_user_message},
                        ],
                    )
                    file_patches, had_trunc, had_missing, had_sanity = (
                        merge_edits_to_file_patches(
                            validated_pairs,
                            edit_bundle.edits,
                            files,
                        )
                    )
                    if had_sanity:
                        had_sanity_reject_any = True
                        emit(
                            fix_id,
                            "warn",
                            f"{label}: rejected edit(s) — would drop return/raise or HTTPException "
                            f"without equivalent replacement",
                            branch=f"fix-{group_id}",
                        )
                    if file_patches:
                        break
                    if attempt < 2:
                        emit(
                            fix_id,
                            "warn",
                            f"{label}: edit step — no validated patches (retry {attempt + 1}/2)",
                            branch=f"fix-{group_id}",
                        )
                        if had_trunc:
                            extra_edit_system += _PATCH_EDIT_RETRY + _PATCH_EDIT_RETRY_SYNTAX
                        elif had_missing:
                            extra_edit_system += _PATCH_EDIT_RETRY_GROUNDING
                        elif had_sanity:
                            extra_edit_system += (
                                "\n\nYour prior edit was rejected: do not remove return statements, "
                                "raise, or HTTPException branches unless you replace them with "
                                "equivalent behavior on every path."
                            )
                        else:
                            extra_edit_system += _PATCH_EDIT_RETRY

            if edit_bundle:
                note_parts.append((edit_bundle.notes or "").strip())
                controls_added = (edit_bundle.controls_added or "").strip()
                tests_touched = (edit_bundle.tests_touched or "").strip()
                residual_risk = (edit_bundle.residual_risk or "").strip()
            merged_notes = " ".join(part for part in note_parts if part).strip()
            if not file_patches and validated_pairs:
                merged_notes = (
                    f"{merged_notes} Step 2 did not yield complete patches "
                    f"(truncation, missing indices, or empty edits)."
                ).strip()
            if not file_patches and search_evidence:
                merged_notes = f"{merged_notes}\n\nRepo-wide hits:\n{search_evidence}".strip()
            if had_sanity_reject_any:
                merged_notes = (
                    f"{merged_notes} Sanitizer: one or more model edits were discarded because "
                    f"they removed return/raise or HTTPException handling without a safe replacement."
                ).strip()

        changed_paths = sorted({p.path for p in file_patches if p.path})

        result = PatchResult(
            group_id=group_id,
            group_label=group_label,
            patches=file_patches,
            notes=merged_notes,
            controls_added=controls_added,
            tests_touched=tests_touched,
            residual_risk=residual_risk,
            changed_paths=changed_paths,
            search_evidence=search_evidence if not file_patches else "",
            locate_confidences=locate_confidences,
        )

        edit_mode = (
            "locate + ReAct edit"
            if FIX_PATCH_REACT_ENABLED
            else "locate + edit"
        )
        emit(
            fix_id,
            "branch_done",
            f"{label}: {len(result.patches)} validated file patch(es) ({edit_mode})",
            branch=f"fix-{group_id}",
        )
        return result.model_dump()

    except Exception as exc:  # noqa: BLE001
        emit(
            fix_id,
            "warn",
            f"{label} patch generation failed: {exc!s:.140}",
            branch=f"fix-{group_id}",
        )
        return PatchResult(
            group_id=group_id,
            group_label=group_label,
            patches=[],
            notes=f"Patch generation failed: {exc!s:.200}",
            search_evidence=repo_wide_search_evidence(
                files,
                collect_evidence_needles_from_findings(group_findings),
            ),
        ).model_dump()
