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
"""

# ── Step 1: locate verbatim regions (no patched_snippet, no diff) ─────────

PATCH_LOCATE_SYSTEM = """\
You are a senior security engineer **locating** code to change (step 1 of 2).
You receive **only this group’s findings** and **ORIGINAL FILES** excerpts.

Task: For each finding you can address, output one `items` row with:
  - `path`: must match a file path from the ### headings in ORIGINAL FILES.
  - `original_snippet`: **exact** contiguous text copied from that file’s excerpt
    (verbatim substring; same whitespace; do not paraphrase or “clean up”).

Rules:
  - Do **not** output patched code, replacements, or diffs — only regions to find.
  - Include enough lines (often a full function, handler, or config stanza) to
    apply the remediation safely, but only text that **literally appears** in the excerpt.
  - If the issue needs more than a one-line tweak (validation, safe defaults, auth
    checks), your `original_snippet` should span the whole region you will need to
    replace so step 2 can apply a **complete** fix in one go.
  - If a finding has no matching file or no verbatim region, skip it and mention in `notes`.
  - Multiple `items` per path are allowed for separate regions.
"""

PATCH_LOCATE_RETRY = """

Retry: Every `original_snippet` must appear **exactly** in ORIGINAL FILES. Copy-paste
from the ``` block; do not invent or summarize.
"""

PATCH_LOCATE_RETRY_2 = """

Final attempt: At least one valid `items` row with path + verbatim `original_snippet`
from the provided excerpts.
"""

# ── Step 2: produce replacements (patched_snippet only; diff computed server-side) ─

PATCH_EDIT_SYSTEM = """\
You are a senior security engineer **applying** security fixes (step 2 of 2).
The user message lists **LOCATE TARGETS**: each `[index]` has a `path` and an
`original_snippet` that is already verified to exist in the repo.

Task: For each index you are fixing, output one `edits` row with:
  - `index`: same integer as in LOCATE TARGETS.
  - `patched_snippet`: the **full** replacement for that `original_snippet` only —
    complete, syntactically valid, balanced brackets/parens, closed strings.
  - `explanation`: one sentence on what changed and why it fixes the finding.

Rules:
  - Do **not** output unified diff — the server computes it.
  - `patched_snippet` must be a drop-in replacement for **only** that `original_snippet`
    block (same span of logic; do not merge unrelated regions).
  - The fix must **meaningfully** address the vulnerability: add the checks, crypto,
    or configuration the finding calls for, not a cosmetic rename or no-op.
  - Preserve behavior outside the security fix; do not delete validation or error
    paths unless the finding explicitly requires it.
  - Dependency files: never relax a safe pin to a looser minimum (e.g. do not replace
    `pkg==2.32.5` with `pkg>=2.31.0`).
  - Emit one edit per index you can fix; omit indices you cannot fix and say why in `notes`.
"""

PATCH_EDIT_RETRY = """

Retry: Each `patched_snippet` must be **complete** (no truncated strings or half-blocks).
Match the `index` to LOCATE TARGETS and replace only that original block.
"""

PATCH_EDIT_RETRY_2 = """

Final attempt: For each listed index, either emit a complete `patched_snippet` or explain in `notes`.
"""

PATCH_EDIT_RETRY_GROUNDING = """

Your prior output was rejected. The `patched_snippet` must replace **exactly** the
`original_snippet` shown for that index — same scope, fully written out.
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
        "apply a minimal in-place fix)\n"
        f"```\n{content}\n```"
    )


def format_fix_excerpt_large_window(
    matched_path: str, lo: int, hi: int, n: int, excerpt: str
) -> str:
    return (
        f"### {matched_path} (lines {lo}-{hi} of {n}; file too large for full paste; "
        "excerpt around cited finding line(s))\n"
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
            f"original_snippet (replace this exact block):\n```\n{orig}\n```"
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
        f"Risk level: {risk_level}\n\n"
        f"FINDINGS TO FIX (group):\n{finding_text}\n\n"
        f"ORIGINAL FILES:\n{files_text}"
        f"{broad_path_hint}"
    )


def format_patch_edit_user(
    report_context: str,
    group_label: str,
    commit_message: str,
    risk_level: str,
    finding_text: str,
    last_target_index: int,
    locate_block: str,
    files_text: str,
) -> str:
    return (
        f"{report_context}\n\n"
        f"---\n"
        f"## Step 2 — apply fixes (this group only)\n"
        f"FIX GROUP: {group_label}\n"
        f"Commit message: {commit_message}\n"
        f"Risk level: {risk_level}\n\n"
        f"FINDINGS TO FIX (group):\n{finding_text}\n\n"
        f"LOCATE TARGETS (indices 0..{last_target_index}):\n{locate_block}\n\n"
        f"ORIGINAL FILES (same excerpts as step 1):\n{files_text}"
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
