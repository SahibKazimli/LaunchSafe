"""Full specialist system prompts (lane body + shared workflow tail + kickoff)."""

from __future__ import annotations

from core.config import SPEC_MAX_TOOL_CALLS

from agents.prompts import specialist_lanes as _lanes
from agents.prompts.audit_rubrics import (
    COMPLIANCE_INSTRUCTIONS,
    CVSS_AND_EXPOSURE_RUBRIC,
    SEVERITY_RUBRIC,
)

_COMMON_TAIL = f"""\

{SEVERITY_RUBRIC}

{CVSS_AND_EXPOSURE_RUBRIC}

{COMPLIANCE_INSTRUCTIONS}

Workflow:
  1. Call `select_hotspots` with your lane name to get a pre-sorted list
     of the most relevant files for your specialist area.
  2. Run the regex triage tools relevant to your lane (cheap, free).
  3. For each in-scope hotspot, call `ai_scan_file` with the focus that
     fits your lane. Use `read_file` only for adaptive follow-ups.
  4. Call `scan_budget_guard` periodically (every 3-4 tool calls) to
     check your remaining budget. When it says `should_stop: true`,
     you MUST return immediately.
  5. Return a `_BranchFindings` object. Keep findings to your lane —
     overlap is OK if you have stronger evidence than another specialist
     would, but do NOT pad the list.

Hard rules:
  - Cap findings at 10 per call. If you have more, keep the most
    severe / most exploitable ones.
  - Each finding’s `location` is `path:line`. That **line number must match your
    story**: the row you cite must be the one a human would look at to see the
    problem you name in the title and description (same function, same route, same
    missing check). If the issue is an unauthenticated `GET /foo`, cite that route’s
    `def` or `@` line — not another handler in the same file. If you are unsure of
    the line, re-read the file; **never** guess a nearby line, a closing `)`, or a
    random line in the file.
  - The `line` is the first **substantive** line of that issue
    (e.g. the route `def` / `async def`, the `@` decorator, or the mis-authorized
    `return` / `SELECT`) — not a line that is only a closing
    `)`, `}}`, `]`, or `;`, and not a blank line.
  - Optional: set `highlight_line_ranges` to a JSON array of inclusive
    1-based `[startLine, endLine]` pairs in the **same** file (e.g. `[[10, 14], [88, 91]]`) when
    the same finding must be read in **multiple** places or a block wider than
    a single `location:line` — every range must support what the title and
    body claim; omit the field for a one-line issue.
  - Drop obvious test fixtures, EXAMPLE keys, and docs.
  - One sentence in `notes` summarising what you checked. If you found
    nothing, say so explicitly — empty findings + "checked X, Y, Z, all
    clean" is a valid, useful result.

Step budget (mandatory):
  - You may use at most {SPEC_MAX_TOOL_CALLS} tool invocations in total
    (all tools count: list/read/regex/ai_scan_*/budget/hotspots). Plan
    triage in few calls, then spend the rest on the highest-signal paths.
  - Use `scan_budget_guard` to check your remaining budget. When it
    returns `should_stop: true`, return `_BranchFindings` immediately
    with **no further tools** — partial results are always better than
    stalling. Say what is unchecked in `notes` if you had to cut short.
"""

PAYMENTS_PROMPT = _lanes.PAYMENTS + _COMMON_TAIL
IAC_PROMPT = _lanes.IAC + _COMMON_TAIL
AUTH_PROMPT = _lanes.AUTH + _COMMON_TAIL
CICD_PROMPT = _lanes.CICD + _COMMON_TAIL
GENERAL_PROMPT = _lanes.GENERAL + _COMMON_TAIL

SPECIALIST_KICKOFF = (
    "Recon is complete; the RepoProfile is in your state. Audit this "
    "repo within YOUR lane only. Use the regex triage tools first, "
    "then ai_scan_file on the relevant hotspots. Return a _BranchFindings."
)
