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
from core.config import (
    FIX_PATCH_MAX_TOKENS,
    FIX_PLAN_MAX_TOKENS,
    FIX_PROMPT_FULL_FILE_MAX_CHARS,
    FIX_REVIEW_MAX_TOKENS,
)
from core import scan_store as _ss
from core.finding_files import (
    build_excerpt_for_fix_prompt,
    find_file_content,
    infer_paths_from_finding_text,
    merge_scan_files_for_fix,
    resolve_path_to_canonical_key,
    resolve_paths_for_findings,
)

from .fix_state import (
    FilePatch,
    FixGroup,
    FixPlan,
    PatchResult,
    PatchReview,
)


def _resolve_target_files_for_group(
    raw_targets: list[str],
    group_findings: list[dict],
    files: dict[str, str],
) -> list[str]:
    """Merge planner targets and finding locations into canonical file keys."""
    keys: list[str] = []
    seen: set[str] = set()
    for target in raw_targets:
        key = resolve_path_to_canonical_key(target, files)
        if key and key not in seen:
            keys.append(key)
            seen.add(key)
    for finding in group_findings:
        key = resolve_path_to_canonical_key(finding.get("location", ""), files)
        if key and key not in seen:
            keys.append(key)
            seen.add(key)
    if not keys and group_findings:
        for key in infer_paths_from_finding_text(group_findings, files):
            if key not in seen:
                keys.append(key)
                seen.add(key)
    return keys


def _rewrite_plan_target_files(
    groups: list[dict],
    findings: list[dict],
    files: dict[str, str],
) -> None:
    """Mutate each group's target_files in place to match real ``files`` keys."""
    for group in groups:
        idxs = group.get("finding_indices") or []
        group_findings = [findings[i] for i in idxs if isinstance(i, int) and i < len(findings)]
        raw = group.get("target_files") or []
        group["target_files"] = _resolve_target_files_for_group(raw, group_findings, files)


def _finding_touches_target_files(
    finding: dict,
    target_keys: list[str],
    files: dict[str, str],
) -> bool:
    """True if this finding maps to a file we are patching in this group."""
    if not target_keys:
        return False
    key_set = set(target_keys)
    key = resolve_path_to_canonical_key(finding.get("location", ""), files)
    if key in key_set:
        return True
    for inf in infer_paths_from_finding_text([finding], files):
        if inf in key_set:
            return True
    return False


def _report_index_for_finding(finding: dict, report_full: list[dict]) -> str:
    for idx, group_finding in enumerate(report_full):
        if not isinstance(group_finding, dict):
            continue
        if finding.get("title") == group_finding.get("title") and finding.get("location") == group_finding.get("location"):
            return str(idx)
    return "?"


def _format_findings_for_patch_prompt(
    primary: list[dict],
    doc_only: list[dict],
    report_full: list[dict] | None = None,
) -> str:
    """Separate repo-backed findings from doc-only / no-file noise for the patch LLM."""
    rf = report_full or []
    chunks: list[str] = []
    if primary:
        chunks.append(
            "\n".join(
                f"- [report #{_report_index_for_finding(f, rf)}] "
                f"({f.get('severity', '?')}) {f.get('title', '?')} "
                f"@ {f.get('location', '?')}\n"
                f"  Description: {(f.get('description', '') or '')[:300]}\n"
                f"  Suggested fix: {(f.get('fix', '') or '')[:400]}"
                for f in primary
            )
        )
    if doc_only:
        chunks.append(
            "---\nThese findings have **no matching source file** in this scan "
            "(e.g. missing policy URL). Do **not** emit FilePatch for them; "
            "only fix the files in ORIGINAL FILES above. You may mention them "
            "in PatchResult.notes:\n"
            + "\n".join(
                f"- [report #{_report_index_for_finding(f, rf)}] "
                f"({f.get('severity', '?')}) {f.get('title', '?')} "
                f"@ {f.get('location', '?')}"
                for f in doc_only
            )
        )
    return "\n\n".join(chunks) if chunks else "(no findings)"


def _patch_dict_is_substantive(patch: dict) -> bool:
    """True if a patch has a real change (snippets differ or diff has +/- lines)."""
    o = (patch.get("original_snippet") or "").strip()
    s = (patch.get("patched_snippet") or "").strip()
    d = (patch.get("diff") or "").strip()
    if o and s and o != s:
        return True
    for line in d.splitlines():
        if line.startswith("+++ ") or line.startswith("--- ") or line.startswith("@@"):
            continue
        if line.startswith("+") and not line.startswith("+++"):
            return True
        if line.startswith("-") and not line.startswith("---"):
            return True
    return False


def _naive_brace_depth(text: str) -> int:
    d = 0
    for c in text:
        if c == "{":
            d += 1
        elif c == "}":
            d -= 1
    return d


def _naive_paren_depth(text: str) -> int:
    d = 0
    for c in text:
        if c == "(":
            d += 1
        elif c == ")":
            d -= 1
    return d


def _last_non_empty_line(text: str) -> str:
    for line in reversed(text.splitlines()):
        if line.strip():
            return line.rstrip()
    return ""


def _patch_looks_incomplete_or_truncated(patch: dict) -> bool:
    """Heuristic: model hit output limits or dropped closing braces (reject, retry)."""
    s = (patch.get("patched_snippet") or "").strip()
    if not s:
        return True
    if _naive_brace_depth(s) != 0:
        return True
    if _naive_paren_depth(s) != 0:
        return True
    last = _last_non_empty_line(s)
    if last.endswith("\\"):
        return True
    # Unterminated string on the last line (common when printf/concat is cut off)
    if last.count('"') % 2 == 1 or last.count("'") % 2 == 1:
        return True
    return False


def _patch_result_has_body(result: PatchResult) -> bool:
    for p in result.patches:
        if _patch_dict_is_substantive(p.model_dump()):
            return True
    return False


def _batch_has_substantive_patches(patch_results: list[dict]) -> bool:
    for pr in patch_results:
        for p in pr.get("patches") or []:
            if isinstance(p, dict) and _patch_dict_is_substantive(p):
                return True
    return False


_SEVERITY_FULL_FILE = frozenset({"medium", "high", "critical"})


def _format_full_report_context(sess: dict[str, Any]) -> str:
    """Full-scan report text so patch LLM aligns with audit, not ad-hoc edits."""
    lines = [
        "## Full audit report (entire scan — use to align code changes with reported issues)",
        f"Grade: {sess.get('report_grade', '?')}",
        f"Overall risk: {sess.get('report_overall_risk', '')}",
        f"Executive summary: {sess.get('report_summary', '')}",
    ]
    top = sess.get("report_top_fixes") or []
    if top:
        lines.append("Top fixes from synthesize:")
        for item in top[:12]:
            lines.append(f"  - {item}")
    full = sess.get("report_findings_full") or []
    lines.append(f"\nAll {len(full)} finding(s) on this scan (index matches report order):")
    for i, f in enumerate(full):
        if not isinstance(f, dict):
            continue
        sev = f.get("severity", "?")
        lines.append(
            f"  [{i}] ({sev}) {f.get('title', '')} @ {f.get('location', '')}"
        )
        desc = (f.get("description") or "").strip()
        if desc:
            lines.append(f"      Detail: {desc[:280]}")
        fx = (f.get("fix") or "").strip()
        if fx:
            lines.append(f"      Report remediation: {fx[:400]}")
    text = "\n".join(lines)
    cap = 32_000
    if len(text) > cap:
        return text[:cap] + "\n...[report context truncated]\n"
    return text


def _file_has_medium_plus_finding(
    matched_path: str,
    excerpt_findings: list[dict],
    files: dict[str, str],
) -> bool:
    """Medium+ findings on this path → always include full ingested file in prompt."""
    for f in excerpt_findings:
        if str(f.get("severity") or "").lower() not in _SEVERITY_FULL_FILE:
            continue
        k = resolve_path_to_canonical_key(f.get("location", ""), files)
        if k == matched_path:
            return True
        for inf in infer_paths_from_finding_text([f], files):
            if inf == matched_path:
                return True
    return False


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
    from core import fix_store as _fs
    fix_session = _fs.get_fix_session(fix_id) or {}
    selected_indices = fix_session.get("finding_indices", [])
    all_findings = scan.get("findings", [])
    if selected_indices:
        findings = [
            all_findings[i]
            for i in selected_indices
            if i < len(all_findings)
        ]
    else:
        # Default: all findings if none explicitly selected
        findings = all_findings

    files = merge_scan_files_for_fix(fix_session, scan)

    keys_preview = list(files.keys())[:5]
    emit(
        fix_id, "info",
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
    for idx, finding in enumerate(findings):
        finding_lines.append(
            f"[{idx}] ({finding.get('severity', '?')}) {finding.get('title', '?')} "
            f"@ {finding.get('location', '?')}\n"
            f"    fix: {(finding.get('fix', '') or '')[:200]}"
        )

    # Also list available files
    files = state.get("files", {})
    file_list = "\n".join(f"  - {p} ({len(c)} bytes)" for p, c in files.items())

    resolved_lines = resolve_paths_for_findings(findings, files)
    resolved_block = ""
    if resolved_lines:
        resolved_block = (
            "\n\nRESOLVED_REPO_PATHS (prefer these exact paths in target_files):\n"
            + "\n".join(f"  - {p}" for p in resolved_lines)
        )

    user_msg = (
        f"Target: {state.get('target', '?')}\n\n"
        f"FINDINGS ({len(findings)}):\n"
        + "\n".join(finding_lines)
        + f"\n\nAVAILABLE FILES ({len(files)}):\n{file_list}"
        + resolved_block
    )

    try:
        llm = get_llm(max_tokens=FIX_PLAN_MAX_TOKENS)
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
            canon = resolve_path_to_canonical_key(f.get("location", ""), files)
            raw = (f.get("location", "") or "").split(":")[0].strip()
            tgt = [canon] if canon else ([raw] if raw else [])
            groups.append(FixGroup(
                group_id=f"fix-{i}",
                label=f.get("title", f"Fix {i}")[:60],
                finding_indices=[i],
                target_files=tgt,
                risk_level="medium",
                commit_message=f"fix: {f.get('title', 'security fix')[:50]}",
            ))
        plan = FixPlan(
            groups=groups,
            execution_order=[g.group_id for g in groups],
            notes="Fallback plan — LLM planning failed, one group per finding.",
        )

    plan_dict = plan.model_dump()
    _rewrite_plan_target_files(plan_dict["groups"], findings, files)

    emit(
        fix_id, "branch_done",
        f"Fix plan: {len(plan.groups)} groups, order: {plan.execution_order}",
        branch="fix-planner",
    )

    return {"fix_plan": plan_dict}


# ── Node 3: Generate Patches ─────────────────────────────────────────


_PATCH_SYSTEM = """\
You are a senior security engineer applying fixes to production code.
You receive the **full audit report** plus a **focus group** of findings and
the original file contents. Implement what the report asks for — do not improvise
by deleting large blocks of logic.

Rules:
  - Make the MINIMAL change that fixes the issue in each file.
  - Preserve ALL existing functionality. Do NOT refactor unrelated code.
  - **Do NOT “fix” by deleting** validation, bounds checks, `malloc`/`free`
    pairs, error handling, `goto cleanup`, socket read loops, or `break` logic
    unless the finding **explicitly** says that code is wrong or unreachable.
    Prefer **adding** checks, tightening bounds, zeroing buffers, fixing
    off-by-ones, or correcting a specific unsafe call — not removing the block.
  - If the report says “add validation” or “harden memory,” **extend** the code;
    do not strip the surrounding allocation/read path.
  - Preserve all comments and documentation unless they are the bug.
  - For each file you modify, provide:
      1. original_snippet: copy-paste a **contiguous** region **verbatim** from the
         file (include 3–8 lines before and after the bug). It must be an **exact**
         substring of the source, not a summary.
      2. patched_snippet: the **same** region after your edit: **every** line that
         stays must appear **unchanged**. Do NOT drop assignments, returns, ports,
         braces `}`, or closing logic that still belongs in that region. If you only
         change one line (e.g. `INADDR_ANY` → loopback), all other lines in the
         snippet must match `original_snippet` except that line.
      3. diff: unified diff you generate from those two snippets
      4. explanation: one sentence — what changed and why it fixes it
  - Generate REAL code in the correct language. No pseudocode, no TODOs.
  - Include new imports in the patched_snippet if needed.
  - If no file content was provided for a finding, skip it and note why
    in the PatchResult.notes field. Do NOT make up code.
  - When file content IS provided below, you MUST emit at least one FilePatch
    per file with non-empty original_snippet, patched_snippet, and diff.
    Do not return an empty patch list for files you were given.
  - If a block is labeled COMPLETE FILE, copy the vulnerable lines verbatim
    into original_snippet and show the same region with your fix in patched_snippet.
  - **Sanity check:** `patched_snippet` must not have far fewer lines than
    `original_snippet` unless you are deliberately deleting dead code called out
    in the finding. Typical bind/config fixes change 1–2 lines only; keep the rest.
  - **Completeness:** Every `patched_snippet` must be syntactically complete in
    isolation: balanced `()` and `{}`, closed string literals, and terminated
    statements (`;` where the language requires). Do not stop mid-`printf` or
    mid-`if`.
"""

_PATCH_RETRY_TAIL = (
    "\n\nRetry / correction: Your previous answer had no real code changes. "
    "You MUST return FilePatch entries with non-empty original_snippet, "
    "patched_snippet, and a unified diff for each file shown under "
    "ORIGINAL FILES. Apply the fix inside the excerpt you were given. "
    "If you change a bind/listen line, keep `sin_port`, `return`, and closing "
    "`}` lines in the same snippet — do not delete them. "
    "Never remove input validation or allocation blocks to “simplify” — fix "
    "the vulnerability in place per the report’s remediation."
)

_PATCH_RETRY_TAIL_2 = (
    "\n\nFinal attempt: Emit ONE FilePatch per file under ORIGINAL FILES. "
    "Each patch must have original_snippet ≠ patched_snippet (real edit). "
    "Ignore doc-only / policy findings in the list footer — they are not files."
)

_PATCH_RETRY_TRUNCATION = (
    "\n\nYour last output was rejected as **truncated or structurally incomplete**: "
    "unbalanced `()` / `{}`, or an **unterminated string** on the last line. "
    "Reply with **complete** `patched_snippet` only — full `printf(\"...\");` lines, "
    "full `if (...) { ... }` including any `break;` / `return` the original had. "
    "Prefer the smallest edit (e.g. add `|| cmd_length > N` to an existing `if`)."
)


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

    from core import fix_store as _fs_fix

    fix_sess = _fs_fix.get_fix_session(fix_id) or {}
    report_context = _format_full_report_context(fix_sess)
    report_full_list = list(fix_sess.get("report_findings_full") or [])

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

        raw_targets = list(group.get("target_files") or [])
        target_keys = _resolve_target_files_for_group(
            raw_targets, group_findings, files,
        )

        code_findings = [
            f for f in group_findings
            if _finding_touches_target_files(f, target_keys, files)
        ]
        doc_only_findings = [f for f in group_findings if f not in code_findings]
        excerpt_findings = code_findings if code_findings else group_findings

        file_sections = []
        missing_files = []
        for path in target_keys:
            matched_path, content = find_file_content(path, files)
            if content:
                cap = FIX_PROMPT_FULL_FILE_MAX_CHARS
                if _file_has_medium_plus_finding(matched_path, excerpt_findings, files):
                    # Always pass the full ingested file for medium+ issues on this path
                    cap = max(cap, len(content) + 128)
                file_sections.append(
                    build_excerpt_for_fix_prompt(
                        matched_path,
                        content,
                        excerpt_findings,
                        files,
                        full_file_max_chars=cap,
                    ),
                )
            else:
                missing_files.append(path)

        if missing_files:
            emit(
                fix_id, "warn",
                f"{group_id}: could not find content for: {', '.join(missing_files[:5])}",
                branch=f"fix-{group_id}",
            )

        has_file_content = bool(file_sections)

        if code_findings:
            finding_text = _format_findings_for_patch_prompt(
                code_findings, doc_only_findings, report_full_list,
            )
        else:
            finding_text = _format_findings_for_patch_prompt(
                group_findings, [], report_full_list,
            )

        if has_file_content:
            files_text = "\n\n".join(file_sections)
        else:
            hint_parts = list(raw_targets) + [f.get("location", "") for f in group_findings]
            cleaned = {h for h in hint_parts if h and str(h).strip().lower() not in ("unknown", "?", "n/a")}
            missing_list = ", ".join(sorted(cleaned)) if cleaned else (
                "no matching repo path (empty or non-path locations); "
                "narrative text did not match any file key"
            )
            files_text = (
                f"(File content not found for: {missing_list}. "
                "Skip this group and note in PatchResult.notes.)"
            )

        user_msg = (
            f"{report_context}\n\n"
            f"---\n"
            f"## Your task (this fix group only)\n"
            f"Implement patches that satisfy the **FINDINGS TO FIX** section below, "
            f"using the **Report remediation** lines from the audit where present. "
            f"Indices in brackets refer to the full report list above.\n\n"
            f"FIX GROUP: {group.get('label', group_id)}\n"
            f"Commit message: {group.get('commit_message', '')}\n"
            f"Risk level: {group.get('risk_level', 'medium')}\n\n"
            f"FINDINGS TO FIX (group):\n{finding_text}\n\n"
            f"ORIGINAL FILES:\n{files_text}"
        )

        try:
            llm = get_llm(max_tokens=FIX_PATCH_MAX_TOKENS)
            structured = llm.with_structured_output(PatchResult)
            fallback_path = target_keys[0] if target_keys else "file"

            def _backfill_patch_diffs(res: PatchResult) -> None:
                for patch in res.patches:
                    if not patch.diff and patch.original_snippet and patch.patched_snippet:
                        use_path = (patch.path or "").strip() or fallback_path
                        patch.diff = _make_diff(
                            use_path,
                            patch.original_snippet,
                            patch.patched_snippet,
                        )

            def _kept_patches_from_result(res: PatchResult) -> tuple[list[dict], list[dict]]:
                """Return (substantive patches, kept patches that pass structural checks)."""
                substantive: list[dict] = []
                kept: list[dict] = []
                for p in res.patches:
                    d = p.model_dump()
                    if not isinstance(d, dict) or not _patch_dict_is_substantive(d):
                        continue
                    substantive.append(d)
                    if not _patch_looks_incomplete_or_truncated(d):
                        kept.append(d)
                return substantive, kept

            extra_sys = ""
            result: PatchResult | None = None
            for attempt in range(3):
                sys_content = _PATCH_SYSTEM + extra_sys
                if attempt == 2:
                    sys_content += _PATCH_RETRY_TAIL_2
                result = structured.invoke([
                    {"role": "system", "content": sys_content},
                    {"role": "user", "content": user_msg},
                ])
                _backfill_patch_diffs(result)
                if not has_file_content:
                    break
                substantive, kept = _kept_patches_from_result(result)
                if kept:
                    break
                if attempt < 2:
                    if substantive:
                        emit(
                            fix_id, "warn",
                            f"{label}: patch snippets incomplete or truncated — retry {attempt + 1}/2",
                            branch=f"fix-{group_id}",
                        )
                        extra_sys += _PATCH_RETRY_TRUNCATION
                    else:
                        emit(
                            fix_id, "warn",
                            f"{label}: patch model returned no substantive edits — retry {attempt + 1}/2",
                            branch=f"fix-{group_id}",
                        )
                        extra_sys += _PATCH_RETRY_TAIL

            _backfill_patch_diffs(result)
            payload = result.model_dump()
            payload["group_id"] = group_id
            substantive, kept = _kept_patches_from_result(
                PatchResult.model_validate({**payload, "group_id": group_id}),
            )
            payload["patches"] = kept
            if has_file_content and substantive and not kept:
                payload["notes"] = (
                    (payload.get("notes") or "").strip()
                    + " Patches were discarded: truncated or structurally incomplete "
                    "(unbalanced braces/parens or unterminated string)."
                ).strip()
            elif has_file_content and not kept:
                hint = (
                    " No substantive patch produced after retries "
                    "(model may have focused on doc-only findings)."
                )
                payload["notes"] = (payload.get("notes") or "").strip() + hint
            result = PatchResult.model_validate(payload)

            emit(
                fix_id, "branch_done",
                f"{label}: {len(result.patches)} substantive file patch(es)",
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
  6. EMPTY DIFFS: If a group claims a file but the diff has no + / - lines,
     that is NOT safe to apply.

Set approved=true only if there is at least one real code change to apply
and the batch is safe. If every diff is empty or cosmetic, approved=false.
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
    for patch_result in patch_results:
        group_id = patch_result.get("group_id", "?")
        patches = patch_result.get("patches", [])
        if not patches:
            review_sections.append(
                f"### {group_id} → (no patch rows)\n"
                f"Notes: {patch_result.get('notes', 'n/a')}"
            )
            continue
        for patch in patches:
            diff = patch.get("diff", "") or "(no diff)"
            review_sections.append(
                f"### {group_id} → {patch.get('path', '?')}\n"
                f"```diff\n{diff[:3000]}\n```\n"
                f"Explanation: {patch.get('explanation', 'n/a')}"
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
        llm = get_llm(max_tokens=FIX_REVIEW_MAX_TOKENS)
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

    rd = review.model_dump()
    if rd.get("approved") and not _batch_has_substantive_patches(patch_results):
        rd["approved"] = False
        w = list(rd.get("warnings") or [])
        w.append(
            "No substantive diff in any patch — nothing to apply. "
            "Re-run fix mode or select fewer / file-backed findings only."
        )
        rd["warnings"] = w
        rd["notes"] = (
            (rd.get("notes") or "").strip()
            + " Batch rejected: empty or non-code patches only."
        ).strip()

    status = "approved" if rd["approved"] else "needs attention"
    emit(
        fix_id, "branch_done",
        f"Review complete: {status}, {len(rd.get('conflicts', []))} conflict(s), "
        f"{len(rd.get('warnings', []))} warning(s)",
        branch="fix-reviewer",
    )

    return {"review_result": rd}
