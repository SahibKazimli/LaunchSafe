"""Fix graph node implementations.

Four nodes, executed sequentially:

  load_context   — reads scan results + original files (no LLM)
  plan_fixes     — LLM groups findings into logical fix batches
  generate_patches — LLM generates unified-diff patches per group
  review_patches — LLM cross-checks patches for conflicts
"""

from __future__ import annotations

import asyncio
import difflib
from collections import defaultdict
from typing import Any

from agents.llm import get_llm
from agents.runtime_log import emit
from core.config import (
    FIX_GROUP_MAX_FILES,
    FIX_PATCH_FILE_PROMPT_MAX_CHARS,
    FIX_PATCH_GROUP_CONTEXT_MAX_CHARS,
    FIX_PATCH_LINE_MARGIN,
    FIX_PATCH_MAX_TOKENS,
    FIX_PLAN_MAX_FINDINGS_PER_GROUP,
    FIX_PLAN_MAX_TOKENS,
    FIX_REVIEW_MAX_TOKENS,
)
from core import scan_store as _ss
from core.finding_files import (
    build_excerpt_for_fix_prompt,
    find_file_content,
    infer_paths_from_finding_text,
    merge_scan_files_for_fix,
    parse_line_number_from_location,
    resolve_path_to_canonical_key,
    resolve_paths_for_findings,
)

from .fix_state import (
    FilePatch,
    FixGroup,
    FixPlan,
    PatchEditBundle,
    PatchEditRow,
    PatchLocateBundle,
    PatchLocateRow,
    PatchResult,
    PatchReview,
)

from agents.prompts.fix_prompts import (
    FIX_PLAN_RESOLVED_PATHS_HEADER,
    PATCH_BROAD_PATH_HINT,
    PATCH_DOC_ONLY_FINDINGS_INTRO,
    PATCH_EDIT_RETRY as _PATCH_EDIT_RETRY,
    PATCH_EDIT_RETRY_2 as _PATCH_EDIT_RETRY_2,
    PATCH_EDIT_RETRY_GROUNDING as _PATCH_EDIT_RETRY_GROUNDING,
    PATCH_EDIT_SYSTEM as _PATCH_EDIT_SYSTEM,
    PATCH_LOCATE_RETRY as _PATCH_LOCATE_RETRY,
    PATCH_LOCATE_RETRY_2 as _PATCH_LOCATE_RETRY_2,
    PATCH_LOCATE_SYSTEM as _PATCH_LOCATE_SYSTEM,
    PLAN_SYSTEM as _PLAN_SYSTEM,
    REVIEW_SYSTEM as _REVIEW_SYSTEM,
    format_fix_group_report_context,
    format_fix_plan_user,
    format_patch_finding_row_doc_only,
    format_patch_finding_row_primary,
    format_patch_edit_user,
    format_patch_file_missing_user,
    format_patch_locate_targets_block,
    format_patch_locate_user,
    format_patch_review_section_diff,
    format_patch_review_section_no_patches,
    format_patch_review_user,
)


def _expand_target_keys_for_group(
    group_findings: list[dict],
    files: dict[str, str],
    base_keys: list[str],
    max_files: int,
) -> list[str]:
    """Union planner targets with every path resolved from the group's findings.

    The planner often lists one file while other findings in the same batch map
    elsewhere — that starves ``api-security``-style groups of the routes they need.
    """
    merged: list[str] = []
    seen: set[str] = set()
    for key in base_keys:
        if key in files and key not in seen:
            merged.append(key)
            seen.add(key)
        if len(merged) >= max_files:
            return merged
    for key in resolve_paths_for_findings(group_findings, files):
        if key in files and key not in seen:
            merged.append(key)
            seen.add(key)
        if len(merged) >= max_files:
            break
    return merged


def _finding_blob_for_hints(findings: list[dict]) -> str:
    return " ".join(
        f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('fix', '')}"
        for finding in findings
        if isinstance(finding, dict)
    ).lower()


def _supplement_api_like_targets(
    files: dict[str, str],
    group_findings: list[dict],
    keys: list[str],
    max_files: int,
) -> list[str]:
    """If findings are API-ish but paths are vague, add likely entrypoint files."""
    if len(keys) >= min(5, max_files):
        return keys
    blob = _finding_blob_for_hints(group_findings)
    if not any(
        w in blob
        for w in (
            "api",
            "http",
            "rest",
            "endpoint",
            "route",
            "graphql",
            "injection",
            "cors",
            "rate limit",
            "csrf",
            "mass assignment",
            "idor",
        )
    ):
        return keys
    hints = (
        "routes",
        "router",
        "/api/",
        "handler",
        "controller",
        "views",
        "app.py",
        "main.py",
        "server",
        "fastapi",
        "flask",
        "express",
    )
    out: list[str] = list(dict.fromkeys(keys))
    seen = set(out)
    scored: list[tuple[int, str]] = []
    for path in files:
        low = path.replace("\\", "/").lower()
        score = sum(1 for h in hints if h in low)
        if score:
            scored.append((score, path))
    for _score, path in sorted(scored, key=lambda x: (-x[0], len(x[1]), x[1])):
        if path not in seen:
            out.append(path)
            seen.add(path)
        if len(out) >= max_files:
            break
    return out


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


_MANIFEST_BASENAMES: frozenset[str] = frozenset(
    s.lower()
    for s in (
        "requirements.txt",
        "requirements.in",
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "go.mod",
        "go.sum",
        "pyproject.toml",
        "poetry.lock",
        "pipfile",
        "pipfile.lock",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "bun.lockb",
        "cargo.toml",
        "cargo.lock",
        "gemfile",
        "gemfile.lock",
        "composer.json",
        "composer.lock",
        "pom.xml",
    )
)


def _file_key_basename(key: str) -> str:
    return (key or "").replace("\\", "/").rstrip("/").split("/")[-1].lower()


def _is_manifest_file_key(key: str) -> bool:
    if not key or not str(key).strip():
        return False
    b = _file_key_basename(key)
    return b in _MANIFEST_BASENAMES


def _best_file_key(finding: dict, files: dict[str, str]) -> str:
    if not isinstance(finding, dict):
        return ""
    key = resolve_path_to_canonical_key(finding.get("location", ""), files)
    if key:
        return key
    inf = infer_paths_from_finding_text([finding], files, max_paths=1)
    return inf[0] if inf else ""


def _group_mixes_manifest_and_code(
    idxs: list[int],
    findings: list[dict],
    files: dict[str, str],
) -> bool:
    has_m, has_c = False, False
    for i in idxs:
        if not isinstance(i, int) or not (0 <= i < len(findings)):
            continue
        key = _best_file_key(findings[i], files)
        if _is_manifest_file_key(key):
            has_m = True
        else:
            has_c = True
        if has_m and has_c:
            return True
    return False


def _risk_for_finding_indices(findings: list[dict], idxs: list[int]) -> str:
    sev: list[str] = []
    for i in idxs:
        if 0 <= i < len(findings) and isinstance(findings[i], dict):
            sev.append((findings[i].get("severity") or "").lower())
    if any(x in ("critical", "high") for x in sev):
        return "high"
    if any(x == "medium" for x in sev):
        return "medium"
    return "low"


def _coerce_findings_into_groups(
    findings: list[dict],
    files: dict[str, str],
    max_per: int,
) -> list[dict[str, Any]]:
    """Deterministic re-batching: one bucket per (dep|code|unresolved) file, chunks of max_per."""
    n = len(findings)
    if n == 0:
        return []
    buckets: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i in range(n):
        f = findings[i] if isinstance(findings[i], dict) else {}
        key = _best_file_key(f, files)
        if _is_manifest_file_key(key):
            bkey: tuple[str, str] = ("dep", key)
        elif key:
            bkey = ("code", key)
        else:
            bkey = ("unres", "unresolved")
        buckets[bkey].append(i)
    for k in buckets:
        buckets[k].sort()
    dep_keys = sorted((k for k in buckets if k[0] == "dep"), key=lambda x: x[1].lower())
    code_keys = sorted((k for k in buckets if k[0] == "code"), key=lambda x: x[1].lower())
    unres_keys = [k for k in buckets if k[0] == "unres"]
    ordered_keys = dep_keys + code_keys + unres_keys
    groups: list[dict[str, Any]] = []
    used_ids: set[str] = set()
    for bkey in ordered_keys:
        indices = buckets[bkey]
        kind, path = bkey
        for chunk_i in range(0, len(indices), max_per):
            chunk = indices[chunk_i : chunk_i + max_per]
            if kind == "unres":
                base = "nolocation"
            else:
                base = _file_key_basename(path) or (path.split("/")[-1] if path else "group")
            pref = "dep" if kind == "dep" else ("fix" if kind == "code" else "unres")
            slug = "".join(
                c if c.isalnum() else ("-" if c in "./\\" else "")
                for c in base
            )
            while "--" in slug:
                slug = slug.replace("--", "-")
            slug = (slug.strip("-")[:40] or "file").lower()
            chunk_num = 1 + chunk_i // max_per
            if chunk_num == 1:
                base_gid = f"{pref}-{slug}"
            else:
                base_gid = f"{pref}-{slug}-{chunk_num}"
            gid = base_gid
            dup = 0
            while gid in used_ids:
                dup += 1
                gid = f"{base_gid}-d{dup}"
            used_ids.add(gid)
            first = findings[chunk[0]] if chunk and isinstance(findings[chunk[0]], dict) else {}
            title = (first.get("title") or "security fix")[:60]
            groups.append(
                {
                    "group_id": gid,
                    "label": title,
                    "finding_indices": chunk,
                    "target_files": [],
                    "risk_level": _risk_for_finding_indices(findings, chunk),
                    "commit_message": f"fix(security): {title[:50]}",
                    "rationale": (
                        "Server-batched: max "
                        f"{max_per} findings per group; dependency files separate from code."
                    ),
                }
            )
    return groups


def _plan_needs_coercion(
    groups: list[dict],
    findings: list[dict],
    files: dict[str, str],
    max_per: int,
) -> bool:
    if not findings or len(findings) <= 1:
        return False
    n = len(findings)
    valid_groups = groups or []
    seen: set[int] = set()
    for g in valid_groups:
        for i in g.get("finding_indices") or []:
            if not isinstance(i, int) or not (0 <= i < n):
                return True
            if i in seen:
                return True
            seen.add(i)
    if seen != set(range(n)):
        return True
    if len(valid_groups) == 1 and n > 1:
        return True
    for g in valid_groups:
        idxs = [i for i in (g.get("finding_indices") or []) if isinstance(i, int) and 0 <= i < n]
        if len(idxs) > max_per:
            return True
        if _group_mixes_manifest_and_code(idxs, findings, files):
            return True
    return False


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


def _should_narrow(
    matched_path: str,
    content: str,
    group_findings: list[dict],
    files: dict[str, str],
) -> bool:
    """Only use narrow cited-region excerpts for large files with explicit line citations."""
    if len(content) <= 8_000:
        return False
    for f in group_findings:
        if not isinstance(f, dict):
            continue
        if resolve_path_to_canonical_key(f.get("location", ""), files) != matched_path:
            continue
        if parse_line_number_from_location(f.get("location", "")) is not None:
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
                format_patch_finding_row_primary(
                    _report_index_for_finding(f, rf),
                    str(f.get("severity", "?")),
                    str(f.get("title", "?")),
                    str(f.get("location", "?")),
                    f.get("description", "") or "",
                    f.get("fix", "") or "",
                )
                for f in primary
            )
        )
    if doc_only:
        chunks.append(
            PATCH_DOC_ONLY_FINDINGS_INTRO
            + "\n".join(
                format_patch_finding_row_doc_only(
                    _report_index_for_finding(f, rf),
                    str(f.get("severity", "?")),
                    str(f.get("title", "?")),
                    str(f.get("location", "?")),
                )
                for f in doc_only
            )
        )
    return "\n\n".join(chunks) if chunks else "(no findings)"


def _patch_dict_is_substantive(patch: dict) -> bool:
    """True only when before/after snippets both exist and actually differ.

    We do **not** trust a model-written ``diff`` alone: the model often emits
    ``---``/``+++``/``@@`` headers plus context lines with no real +/- edits.
    """
    o = (patch.get("original_snippet") or "").strip()
    s = (patch.get("patched_snippet") or "").strip()
    return bool(o and s and o != s)


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


def _batch_has_substantive_patches(patch_results: list[dict]) -> bool:
    for patch_result in patch_results:
        for patch in patch_result.get("patches") or []:
            if isinstance(patch, dict) and _patch_dict_is_substantive(patch):
                return True
    return False


_SEVERITY_FULL_FILE = frozenset({"medium", "high", "critical"})


def _format_group_report_context(
    sess: dict[str, Any],
    group_findings: list[dict],
    report_full: list[dict],
    max_chars: int = FIX_PATCH_GROUP_CONTEXT_MAX_CHARS,
) -> str:
    """Slim audit text: this group’s findings only (saves input tokens vs full report)."""
    rf = report_full or []
    bullet_lines: list[str] = []
    for finding in group_findings:
        if not isinstance(finding, dict):
            continue
        ri = _report_index_for_finding(finding, rf)
        bullet_lines.append(
            f"- [report #{ri}] ({finding.get('severity', '?')}) "
            f"{finding.get('title', '?')} @ {finding.get('location', '?')}"
        )
        desc = (finding.get("description") or "").strip()
        if desc:
            bullet_lines.append(f"  Detail: {desc[:480]}")
        fx = (finding.get("fix") or "").strip()
        if fx:
            bullet_lines.append(f"  Remediation: {fx[:720]}")
    return format_fix_group_report_context(
        str(sess.get("report_grade", "?")),
        str(sess.get("report_overall_risk", "")),
        len(group_findings),
        bullet_lines,
        max_chars,
    )


def _original_snippet_in_file(original: str, content: str) -> bool:
    """True if original appears verbatim in file (normalize CRLF)."""
    o = original or ""
    if not o.strip():
        return False
    if o in content:
        return True
    on = o.replace("\r\n", "\n")
    cn = (content or "").replace("\r\n", "\n")
    return on in cn


def _file_has_medium_plus_finding(
    matched_path: str,
    excerpt_findings: list[dict],
    files: dict[str, str],
) -> bool:
    """Medium+ findings on this path → always include full ingested file in prompt."""
    for finding in excerpt_findings:
        if str(finding.get("severity") or "").lower() not in _SEVERITY_FULL_FILE:
            continue
        key = resolve_path_to_canonical_key(finding.get("location", ""), files)
        if key == matched_path:
            return True
        for inf in infer_paths_from_finding_text([finding], files):
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
        resolved_block = FIX_PLAN_RESOLVED_PATHS_HEADER + "\n".join(
            f"  - {p}" for p in resolved_lines
        )

    user_msg = format_fix_plan_user(
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
                {"role": "user", "content": user_msg},
            ],
        )
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
    if _plan_needs_coercion(
        plan_dict.get("groups") or [],
        findings,
        files,
        FIX_PLAN_MAX_FINDINGS_PER_GROUP,
    ):
        before_n = len(plan_dict.get("groups") or [])
        plan_dict["groups"] = _coerce_findings_into_groups(
            findings, files, FIX_PLAN_MAX_FINDINGS_PER_GROUP,
        )
        plan_dict["execution_order"] = [
            g["group_id"] for g in plan_dict["groups"] if g.get("group_id")
        ]
        coerced_note = (
            f"Server coerced the LLM plan ({before_n} -> {len(plan_dict['groups'])} groups): "
            f"max {FIX_PLAN_MAX_FINDINGS_PER_GROUP} findings per group, "
            f"dependency manifests not mixed with code, every finding included."
        )
        prior = (plan_dict.get("notes") or "").strip()
        plan_dict["notes"] = f"{prior}\n{coerced_note}".strip() if prior else coerced_note
        emit(fix_id, "info", coerced_note, branch="fix-planner")
    _rewrite_plan_target_files(plan_dict["groups"], findings, files)
    # Planner sometimes omits execution_order; default to declared group order.
    if not plan_dict.get("execution_order") and plan_dict.get("groups"):
        plan_dict["execution_order"] = [
            g["group_id"] for g in plan_dict["groups"] if g.get("group_id")
        ]

    emit(
        fix_id, "branch_done",
        f"Fix plan: {len(plan_dict['groups'])} groups, "
        f"order: {plan_dict.get('execution_order', [])}",
        branch="fix-planner",
    )

    return {"fix_plan": plan_dict}


# ── Node 3: Generate Patches ─────────────────────────────────────────


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


def _validated_locate_items(
    items: list[PatchLocateRow],
    files: dict[str, str],
    fallback_path: str,
) -> list[tuple[str, str]]:
    """Return (canonical_path, original_snippet) pairs verified as substrings of file."""
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for it in items:
        p = (it.path or "").strip() or fallback_path
        matched_key, content = find_file_content(p, files)
        orig = it.original_snippet or ""
        if not content or not orig.strip():
            continue
        if not _original_snippet_in_file(orig, content):
            continue
        key = (matched_key or p, orig)
        if key in seen:
            continue
        seen.add(key)
        out.append((matched_key or p, orig))
    return out


def _merge_edits_to_file_patches(
    validated: list[tuple[str, str]],
    edits: list[PatchEditRow],
    files: dict[str, str],
) -> tuple[list[FilePatch], bool, bool]:
    """Merge step-2 edits with validated locates.

    Returns (file_patches, had_truncation_reject, had_missing_edit_index).
    """
    by_idx: dict[int, PatchEditRow] = {}
    for e in edits:
        by_idx[e.index] = e
    out: list[FilePatch] = []
    trunc = False
    missing = False
    for idx, (path, orig_s) in enumerate(validated):
        if idx not in by_idx:
            missing = True
            continue
        row = by_idx[idx]
        pat_raw = row.patched_snippet or ""
        if not pat_raw.strip() or orig_s.strip() == pat_raw.strip():
            continue
        probe = {"original_snippet": orig_s, "patched_snippet": pat_raw}
        if _patch_looks_incomplete_or_truncated(probe):
            trunc = True
            continue
        _, c = find_file_content(path, files)
        if not c or not _original_snippet_in_file(orig_s, c):
            continue
        out.append(
            FilePatch(
                path=path,
                original_snippet=orig_s,
                patched_snippet=pat_raw,
                diff=_make_diff(path, orig_s, pat_raw),
                explanation=row.explanation or "",
            ),
        )
    return out, trunc, missing


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
        target_keys = _expand_target_keys_for_group(
            group_findings, files, target_keys, FIX_GROUP_MAX_FILES,
        )
        target_keys = _supplement_api_like_targets(
            files, group_findings, target_keys, FIX_GROUP_MAX_FILES,
        )

        code_findings = [
            f for f in group_findings
            if _finding_touches_target_files(f, target_keys, files)
        ]
        doc_only_findings = [f for f in group_findings if f not in code_findings]
        excerpt_findings = code_findings if code_findings else group_findings

        report_context = _format_group_report_context(
            fix_sess, group_findings, report_full_list,
        )

        file_sections = []
        missing_files = []
        for path in target_keys:
            matched_path, content = find_file_content(path, files)
            if content:
                # Cap whole-file paste so input leaves room for structured output.
                cap = FIX_PATCH_FILE_PROMPT_MAX_CHARS
                if _file_has_medium_plus_finding(matched_path, excerpt_findings, files):
                    cap = min(max(cap, len(content) + 64), FIX_PATCH_FILE_PROMPT_MAX_CHARS)
                file_sections.append(
                    build_excerpt_for_fix_prompt(
                        matched_path,
                        content,
                        excerpt_findings,
                        files,
                        full_file_max_chars=cap,
                        line_margin=FIX_PATCH_LINE_MARGIN,
                        narrow_to_cited_region=_should_narrow(
                            matched_path, content, excerpt_findings, files
                        ),
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
            files_text = format_patch_file_missing_user(missing_list)

        broad_path_hint = "" if code_findings else PATCH_BROAD_PATH_HINT

        user_msg = format_patch_locate_user(
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
                fix_id, "branch_done",
                f"{label}: skipped (no repo files for this group)",
                branch=f"fix-{group_id}",
            )
            all_results.append(
                PatchResult(
                    group_id=group_id,
                    patches=[],
                    notes=(
                        "Skipped: no matching source files in this scan for this group "
                        "(docs/policy-only or paths that did not resolve). "
                        "Address these findings manually or re-run with paths in locations."
                    ),
                ).model_dump(),
            )
            continue

        try:
            llm = get_llm(max_tokens=FIX_PATCH_MAX_TOKENS)
            fallback_path = target_keys[0] if target_keys else "file"

            # ── Step 1: locate verbatim regions ─────────────────────────
            locate_structured = llm.with_structured_output(PatchLocateBundle)
            extra_loc = ""
            locate_bundle: PatchLocateBundle | None = None
            validated: list[tuple[str, str]] = []
            for attempt in range(3):
                sys_loc = _PATCH_LOCATE_SYSTEM + extra_loc
                if attempt == 2:
                    sys_loc += _PATCH_LOCATE_RETRY_2
                emit(
                    fix_id, "info",
                    f"{label}: LLM locate step (attempt {attempt + 1}/3)…",
                    branch=f"fix-{group_id}",
                )
                locate_bundle = await asyncio.to_thread(
                    locate_structured.invoke,
                    [
                        {"role": "system", "content": sys_loc},
                        {"role": "user", "content": user_msg},
                    ],
                )
                validated = _validated_locate_items(
                    locate_bundle.items, files, fallback_path,
                )
                if validated:
                    break
                if attempt < 2:
                    emit(
                        fix_id, "warn",
                        f"{label}: locate step — no verbatim regions (retry {attempt + 1}/2)",
                        branch=f"fix-{group_id}",
                    )
                    extra_loc += _PATCH_LOCATE_RETRY

            locate_n = len(locate_bundle.items) if locate_bundle else 0
            emit(
                fix_id, "info",
                f"{label}: locate found {len(validated)} verbatim regions "
                f"from {locate_n} locate items",
                branch=f"fix-{group_id}",
            )
            for section in file_sections:
                first_line = (section.split("\n")[0] or "")[:120]
                emit(
                    fix_id, "info",
                    f"{group_id}: file section: {first_line}",
                    branch=f"fix-{group_id}",
                )

            file_patches: list[FilePatch] = []
            note_parts: list[str] = []
            if locate_bundle:
                note_parts.append((locate_bundle.notes or "").strip())

            if not validated:
                hint = " Step 1 produced no snippets that match file text verbatim."
                merged_notes = f"{' '.join(n for n in note_parts if n)}{hint}".strip()
                result = PatchResult(
                    group_id=group_id,
                    patches=[],
                    notes=merged_notes,
                )
            else:
                # ── Step 2: patched_snippet per index ───────────────────
                locate_block = format_patch_locate_targets_block(validated)
                edit_user_msg = format_patch_edit_user(
                    report_context,
                    str(group.get("label", group_id)),
                    str(group.get("commit_message", "")),
                    str(group.get("risk_level", "medium")),
                    finding_text,
                    len(validated) - 1,
                    locate_block,
                    files_text,
                )
                edit_structured = llm.with_structured_output(PatchEditBundle)
                extra_ed = ""
                edit_bundle: PatchEditBundle | None = None
                for attempt in range(3):
                    sys_ed = _PATCH_EDIT_SYSTEM + extra_ed
                    if attempt == 2:
                        sys_ed += _PATCH_EDIT_RETRY_2
                    emit(
                        fix_id, "info",
                        f"{label}: LLM edit step (attempt {attempt + 1}/3)…",
                        branch=f"fix-{group_id}",
                    )
                    edit_bundle = await asyncio.to_thread(
                        edit_structured.invoke,
                        [
                            {"role": "system", "content": sys_ed},
                            {"role": "user", "content": edit_user_msg},
                        ],
                    )
                    fp_list, trunc_bad, miss_bad = _merge_edits_to_file_patches(
                        validated,
                        edit_bundle.edits,
                        files,
                    )
                    if fp_list:
                        file_patches = fp_list
                        break
                    if attempt < 2:
                        emit(
                            fix_id, "warn",
                            f"{label}: edit step — no validated patches (retry {attempt + 1}/2)",
                            branch=f"fix-{group_id}",
                        )
                        if trunc_bad:
                            extra_ed += _PATCH_EDIT_RETRY
                        elif miss_bad:
                            extra_ed += _PATCH_EDIT_RETRY_GROUNDING
                        else:
                            extra_ed += _PATCH_EDIT_RETRY

                if edit_bundle:
                    note_parts.append((edit_bundle.notes or "").strip())
                merged_notes = " ".join(n for n in note_parts if n).strip()
                if not file_patches and validated:
                    merged_notes = (
                        f"{merged_notes} Step 2 did not yield complete patches "
                        f"(truncation, missing indices, or empty edits)."
                    ).strip()

            result = PatchResult(
                group_id=group_id,
                patches=file_patches,
                notes=merged_notes,
            )

            emit(
                fix_id, "branch_done",
                f"{label}: {len(result.patches)} validated file patch(es) "
                f"(2-step locate+edit)",
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
                format_patch_review_section_no_patches(
                    group_id, str(patch_result.get("notes", "n/a"))
                )
            )
            continue
        for patch in patches:
            diff = patch.get("diff", "") or "(no diff)"
            review_sections.append(
                format_patch_review_section_diff(
                    group_id,
                    str(patch.get("path", "?")),
                    diff,
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

    user_msg = format_patch_review_user(review_sections, len(patch_results))

    try:
        llm = get_llm(max_tokens=FIX_REVIEW_MAX_TOKENS)
        structured = llm.with_structured_output(PatchReview)
        emit(
            fix_id, "info",
            "Calling model for patch review…",
            branch="fix-reviewer",
        )
        review: PatchReview = await asyncio.to_thread(
            structured.invoke,
            [
                {"role": "system", "content": _REVIEW_SYSTEM},
                {"role": "user", "content": user_msg},
            ],
        )
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
