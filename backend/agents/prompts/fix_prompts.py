"""Prompts for the Phase-2 fix graph (plan → patch → review)."""

from __future__ import annotations

PLAN_SYSTEM = """\
You are a senior security engineer planning a coordinated fix session.
You receive a list of security findings from an audit. Your job is to
group them into logical fix batches that can be applied together.

Rules:
  - Findings in the SAME FILE should be in the same group.
  - Related findings across files (e.g. auth config + auth middleware) may
    share one group **only** if the group has at most 5 findings and you do
    **not** mix dependency/manifest files with application code (see hard limits
    below). Prefer separate groups per file when in doubt.
  - For each group, **target_files** must include **every** path from
    RESOLVED_REPO_PATHS that matches **any** finding placed in that group.
    Do not omit a file that a grouped finding maps to.
  - Order groups by dependency: config/dependency fixes first, then
    code that reads the config.
  - Each group gets a risk_level:
      "low"    — formatting, headers, documentation
      "medium" — logic changes, input validation
      "high"   — auth/payment/crypto/session changes
  - Each group gets a conventional commit message.
  - Keep groups focused. 2-6 findings per group is typical.
    Don't put everything in one mega-group.
  - HARD LIMIT: No group may contain more than 5 findings.
  - HARD LIMIT: Dependency/manifest files (e.g. requirements.txt, package.json,
    package-lock.json, go.mod, go.sum, pyproject.toml, poetry.lock) must be in
    their **own** separate group — never mixed with code findings.
  - Code findings (auth, injection, CORS, rate limiting, and similar) must be
    grouped **by file** (one group per affected source file), not by broad
    theme such as "dependency-update" or "CVE" when only some items are
    manifest bumps.
  - If you would output only 1 group for 6+ findings, you have made an error:
    re-split into multiple groups that obey the limits above.
  - **Every group MUST set:**
      - ``group_id``: short unique **kebab-case slug from the main issue** (not generic
        placeholders). Examples: ``idor-user-profile``, ``sql-injection-login-handler``.
      - ``label``: a **human-readable one-line title** shown in the UI (usually the
        finding title, e.g. "Broken object-level authorization on user data").
    Never emit an empty ``group_id`` or ``{}`` for a group — both fields are required.
"""

# ── Step 1: semantic locate (no patched_snippet, no diff) ─────────

PATCH_LOCATE_SYSTEM = """\
You are a senior security engineer **locating** code to change (step 1 of 2).
You receive **only this group’s findings** and **ORIGINAL FILES** excerpts.

**Critical:** Reported line numbers may be stale. Treat locations as *hints*.
Find the **semantically correct** implementation: route decorators, handler names,
router registrations, and data-access code that match the finding — even if the
excerpt does not match the audit line numbers.

Task: For each finding you can address, output one `items` row with:
  - `path`: must match a file path from the ### headings in ORIGINAL FILES.
  - `original_snippet`: the **best contiguous block** from the excerpt that covers
    the vulnerable behavior (copy from the ``` block when possible). If the excerpt
    is misaligned, paste the closest matching block you see and rely on anchors below.
  - `anchor_route`: HTTP route if applicable, e.g. `GET /users/{user_id}` or `/search/chunks`.
  - `anchor_symbols`: Python function/method names for the handler or data layer.
  - `confidence`: 0.0–1.0 — how sure you are this maps to the finding.

Rules:
  - Do **not** output patched code, replacements, or diffs — only regions to find.
  - Prefer a **large enough** region to edit: full handler, whole route cluster, middleware
    section, `FastAPI()` app setup, or config block — not a single line — whenever the fix
    needs broader context (CSP headers, JWT validation, auth dependencies, etc.).
  - If you cannot match text exactly, still fill `anchor_route` / `anchor_symbols`;
    the server will align to real code using the full ingested file.
  - Multiple `items` per path are allowed for separate regions.
  - A response that only explains why nothing can be found is **invalid** unless
    the behavior truly does not exist in ORIGINAL FILES — then say so in `notes`.
"""

PATCH_LOCATE_RETRY = """

Retry: Provide at least one `items` row with a real `path`, a concrete `original_snippet`
from the excerpt (best-effort), and **anchor_route** or **anchor_symbols** so the
server can resolve stale citations.
"""

PATCH_LOCATE_RETRY_2 = """

Final attempt: Emit one valid `items` row: path + snippet (from the file excerpt) +
anchors. Do not refuse solely because audit line numbers differ from the file.
"""

PATCH_TEMPLATE_IDOR = """
**IDOR / ownership:** Ensure the authenticated subject may only access their own
resource (or admins). Add an explicit check comparing `current_user.id` (or equivalent)
to the resource owner id before returning data; return 403 otherwise.
"""

PATCH_TEMPLATE_SEARCH_LEAK = """
**Unauthenticated search / data leak:** Require an authentication dependency on the
route; filter queries by tenant or user id in the data layer; deny by default when
scope is missing.
"""

PATCH_TEMPLATE_BAC = """
**Broken access control:** Prefer a centralized authorization helper (e.g. a single
function or dependency) invoked from the handler instead of ad-hoc checks scattered
only in some branches.
"""

PATCH_FALLBACK_INTRO = """
---
**Defense-in-depth templates** (use when anchors are weak; still produce a real patch
in the listed LOCATE TARGETS, not rationale-only):
"""

# ── Step 2: produce replacements (patched_snippet only; diff computed server-side) ─

PATCH_EDIT_SYSTEM = """\
You are a senior security engineer **applying** security fixes (step 2 of 2).
The user message lists **LOCATE TARGETS**: each `[index]` has a `path` and an
`original_snippet` that the server **verified** exists in the repo (semantic alignment
may have adjusted stale excerpts).

Task: For each index you are fixing, output one `edits` row with:
  - `index`: same integer as in LOCATE TARGETS.
  - `patched_snippet`: the **full** replacement for that index’s `original_snippet`
    (the verified contiguous span from step 1). That span may be **many lines** —
    entire functions, route groups, or app factory sections are fine. The snippet must be
    complete, syntactically valid, balanced brackets/parens, closed strings.
  - `explanation`: one sentence on what changed and why it fixes the finding.

Also set on the structured output root (not inside each edit):
  - `controls_added`: concrete security controls you introduced (authz, ownership,
    scoping, deny-by-default). Use `none` only if inapplicable.
  - `tests_touched`: tests or assertions to add (file names or scenarios); `none`
    if the snapshot has no test layout.
  - `residual_risk`: what could still go wrong after this patch.

Rules:
  - Do **not** output unified diff — the server computes it.
  - `patched_snippet` must replace **exactly** the `original_snippet` text shown for that
    index (engine constraint), but that block can be **large**. Do **not** shrink the fix
    to the smallest possible edit when a broader change is needed — **correct and
    durable** beats minimal line churn. Stay on-topic for this finding (no unrelated refactors).
  - The fix must **meaningfully** address the vulnerability: add the checks, crypto,
    or configuration the finding calls for, not a cosmetic rename or no-op.
  - Preserve behavior outside the security fix; do not delete validation or error
    paths unless the finding explicitly requires it.
  - **Never remove** ``return`` statements, ``raise`` / ``HTTPException``, or
    not-found handling unless you **replace** them with equivalent behavior on all
    code paths (a function that returned a row must still return or raise).
  - Dependency files: never relax a safe pin to a looser minimum (e.g. do not replace
    `pkg==2.32.5` with `pkg>=2.31.0`).
  - Emit one edit per index you can fix; omit indices you cannot fix and say why in `notes`.
  - Output that only explains why no change was made is **invalid** unless the
    vulnerable code is truly absent from ORIGINAL FILES.
  - **Never** paste unified-diff syntax into `patched_snippet`: no lines starting with
    `+`, `-`, `@@`, `---`, or `+++`; no merged `-foo+bar` on one line. Output only
    valid source code as it should exist after the fix.
"""

PATCH_EDIT_RETRY = """

Retry: Each `patched_snippet` must be **complete** (no truncated strings or half-blocks).
Match the `index` to LOCATE TARGETS. The replacement may be long — include the full
revised function/section if that is what a proper fix requires.
"""

PATCH_EDIT_RETRY_2 = """

Final attempt: For each listed index, either emit a complete `patched_snippet` or explain in `notes`.
"""

PATCH_EDIT_RETRY_GROUNDING = """

Your prior output was rejected. The `patched_snippet` must replace **exactly** the full
`original_snippet` shown for that index (verbatim span), fully written out — size is not
a problem; incompleteness or truncation is.
"""

PATCH_EDIT_RETRY_SYNTAX = """

Your prior edit was rejected: applied to the file it produced **invalid Python** (syntax
error), contained diff markers (+/- lines), or the replace span was ambiguous. Emit only
legal source code; include needed imports/symbols; close all parens/brackets/strings.
"""

# ── Step 2 (ReAct): tool-grounded edits — no full-file paste in user message ─

PATCH_REACT_EDIT_SYSTEM = """\
You are a senior security engineer **applying** security fixes (step 2 of 2).
You can **explore the repo with tools**, then return a structured **PatchEditBundle**
(same schema as a single-shot edit model).

Tools (use them):
  - `list_repo_files` — paths + sizes in the ingested snapshot.
  - `grep_repo` — literal substring search across files (quick discovery).
  - `fix_read_file` / `fix_read_files` — read file bodies from the snapshot (prefer batch).

**Grounding rule (mandatory):** Before you return your final structured output, you **must**
call `fix_read_file` or `fix_read_files` at least once for **every distinct file path**
listed in LOCATE TARGETS that you patch (every `index` you include in `edits`). If you
skip this, the server will **discard** your patches. `list_repo_files` and `grep_repo` do
**not** count as reading a file.

Task: For each locate index you fix, output one `edits` row:
  - `index`: integer from LOCATE TARGETS.
  - `patched_snippet`: full replacement for that row's `original_snippet` (must match the
    **verified** text from your tool reads — excerpts in the user message may be truncated).
  - `explanation`: one sentence.

Also set on the root object: `controls_added`, `tests_touched`, `residual_risk`, `notes`.

Same rules as non-tool mode:
  - No unified diff in `patched_snippet`; no `+`/`-` line markers or merged `-a+b` lines.
  - Meaningful security fix — not comments-only or cosmetic renames for auth issues.
  - Never remove `return` / `raise` / `HTTPException` without equivalent behavior.
  - Dependency pins: never downgrade a `pkg==version` pin.
"""

REVIEW_SYSTEM = """\
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


def format_fix_excerpt_narrow_cited(
    matched_path: str,
    lo: int,
    hi: int,
    n: int,
    excerpt: str,
) -> str:
    return (
        f"### {matched_path} (lines {lo}-{hi} of {n}; excerpt around cited finding — "
        "copy `original_snippet` only from this block)\n"
        f"```\n{excerpt}\n```"
    )


def format_fix_excerpt_full_file(
    matched_path: str, n: int, char_len: int, content: str
) -> str:
    return (
        f"### {matched_path} (COMPLETE FILE — {n} lines, {char_len} chars; "
        "you may change whole functions, route groups, middleware/CORS/CSP/JWT setup, "
        "or other large sections — prefer a **complete** fix over the smallest diff)\n"
        f"```\n{content}\n```"
    )


def format_fix_excerpt_large_window(
    matched_path: str, lo: int, hi: int, n: int, excerpt: str
) -> str:
    return (
        f"### {matched_path} (lines {lo}-{hi} of {n}; file too large for full paste; "
        "excerpt around cited finding — expand locate/edit to the full handler or section "
        "if the fix needs more than this window)\n"
        f"```\n{excerpt}\n```"
    )


FIX_EXCERPT_TRUNCATED_HEAD_NOTE = (
    "\n...[truncated — file exceeds full-file prompt cap and has no line "
    "numbers; showing start only]\n"
)


def format_fix_excerpt_head_only(
    matched_path: str, n: int, byte_len: int, excerpt: str
) -> str:
    return (
        f"### {matched_path} ({n} lines, {byte_len} bytes — excerpt only)\n"
        f"```\n{excerpt}\n```"
    )


# ── Fix graph user messages (plan / patch / review) ───────────────────────────


def format_fix_plan_user(
    target: str,
    findings_block: str,
    n_findings: int,
    n_files: int,
    files_listing: str,
    resolved_block: str,
) -> str:
    return (
        f"Target: {target}\n\n"
        f"FINDINGS ({n_findings}):\n{findings_block}"
        f"\n\nAVAILABLE FILES ({n_files}):\n{files_listing}"
        + resolved_block
    )


FIX_PLAN_RESOLVED_PATHS_HEADER = (
    "\n\nRESOLVED_REPO_PATHS (prefer these exact paths in target_files):\n"
)


def format_patch_finding_row_primary(
    report_idx: str,
    severity: str,
    title: str,
    location: str,
    description: str,
    suggested_fix: str,
    desc_max: int = 300,
    fix_max: int = 400,
) -> str:
    return (
        f"- [report #{report_idx}] ({severity}) {title} @ {location}\n"
        f"  Description: {description[:desc_max]}\n"
        f"  Suggested fix: {suggested_fix[:fix_max]}"
    )


def format_patch_finding_row_doc_only(
    report_idx: str,
    severity: str,
    title: str,
    location: str,
) -> str:
    return (
        f"- [report #{report_idx}] ({severity}) {title} @ {location}"
    )


PATCH_DOC_ONLY_FINDINGS_INTRO = (
    "---\nThese findings have **no matching source file** in this scan "
    "(e.g. missing policy URL). Do **not** emit FilePatch for them; "
    "only fix the files in ORIGINAL FILES above. You may mention them "
    "in PatchResult.notes:\n"
)


def format_patch_file_missing_user(missing_list: str) -> str:
    return (
        f"(File content not found for: {missing_list}. "
        "Skip this group and note in PatchResult.notes.)"
    )


PATCH_BROAD_PATH_HINT = (
    "\n\n**Path hint:** Some findings here may not cite an exact file. "
    "Search the ORIGINAL FILES for behavior matching the issue (routes, "
    "handlers, middleware, validation) and patch there — do not skip "
    "the group if source files are shown above."
)


def format_patch_locate_targets_block(validated: list[tuple[str, str]]) -> str:
    blocks: list[str] = []
    for i, (path, orig) in enumerate(validated):
        blocks.append(
            f"#### LOCATE TARGET [{i}] path=`{path}`\n"
            f"original_snippet (replace this **entire** verified block — may be many lines):\n```\n{orig}\n```"
        )
    return "\n\n".join(blocks)


def format_patch_locate_user(
    report_context: str,
    group_label: str,
    commit_message: str,
    risk_level: str,
    finding_text: str,
    files_text: str,
    broad_path_hint: str,
) -> str:
    return (
        f"{report_context}\n\n"
        f"---\n"
        f"## Your task (this fix group only)\n"
        f"Implement patches that satisfy the **FINDINGS TO FIX** section below, "
        f"using the **Remediation** lines where present. "
        f"[report #N] matches the scan’s finding order.\n\n"
        f"FIX GROUP: {group_label}\n"
        f"Commit message: {commit_message}\n"
        f"Risk level: {risk_level}\n"
        f"(Step 1: locate **large** regions when needed — whole functions, route blocks, "
        f"app/middleware setup — not single-line snippets if the fix requires more.)\n\n"
        f"FINDINGS TO FIX (group):\n{finding_text}\n\n"
        f"ORIGINAL FILES:\n{files_text}"
        f"{broad_path_hint}"
    )


def remediation_templates_for_findings(findings: list[dict]) -> str:
    """Return extra template text inferred from vuln class keywords."""
    blob = " ".join(
        str(finding.get("title") or "")
        + " "
        + str(finding.get("description") or "")
        for finding in findings
        if isinstance(finding, dict)
    ).lower()
    chunks: list[str] = []
    if any(
        keyword in blob
        for keyword in (
            "idor",
            "insecure direct object",
            "object reference",
            "authorization",
        )
    ):
        chunks.append(PATCH_TEMPLATE_IDOR.strip())
    if any(
        keyword in blob
        for keyword in (
            "unauthenticated",
            "search",
            "vector",
            "data leak",
            "leak",
            "exposure",
            "tenant",
        )
    ):
        chunks.append(PATCH_TEMPLATE_SEARCH_LEAK.strip())
    if any(
        keyword in blob
        for keyword in (
            "access control",
            "broken access",
            "privilege",
            "escalation",
            "forbidden",
        )
    ):
        chunks.append(PATCH_TEMPLATE_BAC.strip())
    if not chunks:
        return ""
    return PATCH_FALLBACK_INTRO + "\n".join(chunks)


def format_patch_edit_user(
    report_context: str,
    group_label: str,
    commit_message: str,
    risk_level: str,
    finding_text: str,
    last_target_index: int,
    locate_block: str,
    files_text: str,
    remediation_templates: str = "",
) -> str:
    extra = f"\n{remediation_templates}" if remediation_templates.strip() else ""
    return (
        f"{report_context}\n\n"
        f"---\n"
        f"## Step 2 — apply fixes (this group only)\n"
        f"FIX GROUP: {group_label}\n"
        f"Commit message: {commit_message}\n"
        f"Risk level: {risk_level}\n"
        f"(Step 2: `patched_snippet` may be **long** — refactor whole sections if that is "
        f"what a correct fix needs; do not under-shoot for a tiny diff.)\n\n"
        f"FINDINGS TO FIX (group):\n{finding_text}\n\n"
        f"LOCATE TARGETS (indices 0..{last_target_index}):\n{locate_block}\n\n"
        f"ORIGINAL FILES (same excerpts as step 1):\n{files_text}"
        f"{extra}"
    )


def format_patch_edit_user_react(
    report_context: str,
    group_label: str,
    commit_message: str,
    risk_level: str,
    finding_text: str,
    last_target_index: int,
    locate_block: str,
    remediation_templates: str = "",
) -> str:
    """Step-2 user message when using the ReAct patch agent (no inlined file bodies)."""
    extra = f"\n{remediation_templates}" if remediation_templates.strip() else ""
    return (
        f"{report_context}\n\n"
        f"---\n"
        f"## Step 2 — apply fixes (this group only) — **use read tools**\n"
        f"FIX GROUP: {group_label}\n"
        f"Commit message: {commit_message}\n"
        f"Risk level: {risk_level}\n"
        f"Full file bodies are **not** inlined below. Call `fix_read_file` / `fix_read_files` "
        f"for each path in LOCATE TARGETS before returning your PatchEditBundle.\n\n"
        f"FINDINGS TO FIX (group):\n{finding_text}\n\n"
        f"LOCATE TARGETS (indices 0..{last_target_index}):\n{locate_block}\n"
        f"{extra}"
    )


def format_patch_review_section_no_patches(group_id: str, notes: str) -> str:
    return f"### {group_id} → (no patch rows)\nNotes: {notes}"


def format_patch_review_section_diff(
    group_id: str,
    path: str,
    diff: str,
    explanation: str,
    diff_max_chars: int = 3000,
) -> str:
    clipped = (diff or "")[:diff_max_chars]
    return (
        f"### {group_id} → {path}\n"
        f"```diff\n{clipped}\n```\n"
        f"Explanation: {explanation}"
    )


def format_patch_review_user(review_sections: list[str], n_groups: int) -> str:
    return (
        f"PATCHES TO REVIEW ({len(review_sections)} files across "
        f"{n_groups} groups):\n\n"
        + "\n\n---\n\n".join(review_sections)
    )


def format_fix_group_report_context(
    report_grade: str,
    overall_risk: str,
    n_findings: int,
    finding_bullet_lines: list[str],
    max_chars: int,
) -> str:
    lines = [
        "## Audit context (this fix group only)",
        f"Scan grade: {report_grade} | Overall risk: {overall_risk}",
        f"Findings in this group ({n_findings}); [report #] ties to scan list:",
        *finding_bullet_lines,
    ]
    text = "\n".join(lines)
    if len(text) > max_chars:
        return text[:max_chars] + "\n...[group context truncated]\n"
    return text
