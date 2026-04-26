"""Centralised configuration for the LaunchSafe agent layer.

Every tunable constant lives here.  Modules import what they need instead
of defining their own defaults.

**Cost tuning:** Default provider is **Anthropic Claude** (set
``ANTHROPIC_API_KEY``). Override at runtime with env vars
(``LAUNCHSAFE_<KEY>``). The largest savings are usually
``LAUNCHSAFE_SPEC_MAX_TOOL_CALLS`` (fewer tool round-trips per
specialist) and output token caps on recon / synth / ai_scan / fix. For
higher quality on large patches, set ``LAUNCHSAFE_LLM_MODEL`` to a
larger model and optionally raise ``LAUNCHSAFE_FIX_PATCH_MAX_TOKENS``.
"""

from __future__ import annotations

import os
from typing import Any



# Env helpers 

def _env_str(key: str, default: str) -> str:
    return os.environ.get(f"LAUNCHSAFE_{key}", default)


def _env_int(key: str, default: int) -> int:
    raw = os.environ.get(f"LAUNCHSAFE_{key}")
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _env_float(key: str, default: float) -> float:
    raw = os.environ.get(f"LAUNCHSAFE_{key}")
    if raw is None:
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


def spec_react_recursion_limit() -> int:
    """LangGraph `recursion_limit` is graph super-steps, not tool-call count.

    `create_react_agent` does multiple internal steps per tool round (model,
    tool execution, possible structured output). Tuning
    `LAUNCHSAFE_SPEC_RECURSION_LIMIT` down to save cost often breaks this
    relation and triggers "Recursion limit ... without hitting a stop
    condition" while the model still has tools left. To save credits, lower
    `LAUNCHSAFE_SPEC_MAX_TOOL_CALLS` instead; this function still ensures
    the graph can finish after that many *invocation* rounds.
    """
    per_tool = 3
    return max(
        SPEC_RECURSION_LIMIT,
        per_tool * max(SPEC_MAX_TOOL_CALLS, 1) + 18,
    )


# LLM / agent knobs


# Default: cheap Claude. Use e.g. claude-3-5-sonnet-20241022 for heavier scans.
LLM_MODEL: str             = _env_str("LLM_MODEL", "claude-3-5-haiku-20241022")

SPEC_RECURSION_LIMIT: int   = _env_int("SPEC_RECURSION_LIMIT", 24)
SPEC_MAX_TOKENS: int        = _env_int("SPEC_MAX_TOKENS", 1024)
# Primary credit knob: agents are instructed to use at most this many tool
# invocations; see spec_react_recursion_limit() for LangGraph *step* count.
SPEC_MAX_TOOL_CALLS: int    = _env_int("SPEC_MAX_TOOL_CALLS", 7)

RECON_MAX_TOKENS: int       = _env_int("RECON_MAX_TOKENS", 1024)
SYNTH_MAX_TOKENS: int       = _env_int("SYNTH_MAX_TOKENS", 512)
AI_SCAN_MAX_TOKENS: int     = _env_int("AI_SCAN_MAX_TOKENS", 1024)

# Phase-2 fix graph (separate caps so patch generation can stay higher than plan/review)
FIX_PLAN_MAX_TOKENS: int    = _env_int("FIX_PLAN_MAX_TOKENS", 768)
# Large patches may need a higher cap via env (trade-off vs. credits).
FIX_PATCH_MAX_TOKENS: int   = _env_int("FIX_PATCH_MAX_TOKENS", 4096)
FIX_REVIEW_MAX_TOKENS: int  = _env_int("FIX_REVIEW_MAX_TOKENS", 512)
# When an ingested file is at most this many characters, the fix prompt includes
# the **entire** file (not an excerpt). Matches typical ingest cap.
FIX_PROMPT_FULL_FILE_MAX_CHARS: int = _env_int(
    "FIX_PROMPT_FULL_FILE_MAX_CHARS",
    200_000,
)
# Cap how many distinct files one fix group can load (planner + inferred paths).
FIX_GROUP_MAX_FILES: int = _env_int("FIX_GROUP_MAX_FILES", 14)
# Max findings per group after planning; the server coerces the LLM plan to honor this.
FIX_PLAN_MAX_FINDINGS_PER_GROUP: int = _env_int("FIX_PLAN_MAX_FINDINGS_PER_GROUP", 5)
# Patch LLM: only this group’s findings in report context (not full audit).
FIX_PATCH_GROUP_CONTEXT_MAX_CHARS: int = _env_int(
    "FIX_PATCH_GROUP_CONTEXT_MAX_CHARS",
    8_000,
)
# Patch LLM: above this size, use line-window excerpt not whole file (saves input tokens).
FIX_PATCH_FILE_PROMPT_MAX_CHARS: int = _env_int(
    "FIX_PATCH_FILE_PROMPT_MAX_CHARS",
    32_000,
)
# Lines before/after cited finding line(s) in patch prompts (tight window vs whole file).
FIX_PATCH_LINE_MARGIN: int = _env_int("FIX_PATCH_LINE_MARGIN", 16)
# How many fix groups may run LLM locate+edit concurrently (semaphore). 1 = sequential.
FIX_MAX_CONCURRENT_PATCH_GROUPS: int = _env_int("FIX_MAX_CONCURRENT_PATCH_GROUPS", 3)
# When 1, narrow patch prompts to cited line windows for huge files (can miss stale lines).
# Default 0: prefer wider windows so semantic locate can recover from bad citations.
FIX_PROMPT_NARROW_TO_CITED: int = _env_int("FIX_PROMPT_NARROW_TO_CITED", 0)
# Sampling temperature for fix patch LLM (0 = deterministic). Scan/plan may still use defaults.
FIX_PATCH_LLM_TEMPERATURE: float = _env_float("FIX_PATCH_LLM_TEMPERATURE", 0.0)
# When 1, reject .py patches whose replacement breaks ``compile()`` on the full file.
# Set 0 only to debug (may allow broken patches through).
FIX_PATCH_VERIFY_PYTHON_COMPILE: int = _env_int("FIX_PATCH_VERIFY_PYTHON_COMPILE", 1)
# When 1, step-2 patch generation uses a ReAct loop (read/search tools) and rejects
# patches unless every edited path was read via tools (see fix_patch_react).
FIX_PATCH_REACT_ENABLED: int = _env_int("FIX_PATCH_REACT_ENABLED", 1)
# If tool-grounding fails or the react agent returns no structured bundle, fall back
# to the legacy single-shot edit LLM (full excerpts in prompt).
FIX_PATCH_REACT_FALLBACK_LEGACY: int = _env_int("FIX_PATCH_REACT_FALLBACK_LEGACY", 1)
# Max bytes per file returned by fix-patch read tools (large handlers).
FIX_PATCH_REACT_READ_CAP: int = _env_int("FIX_PATCH_REACT_READ_CAP", 80_000)
# Total cap for fix_read_files batch (bytes of raw content before JSON).
FIX_PATCH_REACT_BATCH_BYTES: int = _env_int("FIX_PATCH_REACT_BATCH_BYTES", 240_000)
# LangGraph super-steps for the fix-patch ReAct subgraph. Lower = shorter wall-clock per
# group (may hit the cap and fall back to legacy excerpt-based edit sooner). Raise via env
# if groups often need more tool rounds (e.g. large manifests).
FIX_PATCH_REACT_RECURSION_LIMIT: int = _env_int("FIX_PATCH_REACT_RECURSION_LIMIT", 30)


def fix_patch_react_recursion_limit() -> int:
    """Clamp so env can go below former default without forcing a high floor."""
    return max(10, FIX_PATCH_REACT_RECURSION_LIMIT)

# Fewer files per ``select_hotspots`` → fewer follow-up reads / AI scans
SELECT_HOTSPOT_MAX_FILES: int = _env_int("SELECT_HOTSPOT_MAX_FILES", 6)



# Truncation 

MAX_FILE_BYTES: int          = _env_int("MAX_FILE_BYTES", 16_000)
MAX_CICD_BUNDLE_BYTES: int   = _env_int("MAX_CICD_BUNDLE_BYTES", 40_000)
MAX_AUTH_BUNDLE_BYTES: int   = _env_int("MAX_AUTH_BUNDLE_BYTES", 40_000)
MAX_INGEST_FILE_BYTES: int   = _env_int("MAX_INGEST_FILE_BYTES", 200_000)

MAX_BATCH_BYTES: int         = _env_int("MAX_BATCH_BYTES", 96_000)
MAX_FILES_PER_BATCH: int     = _env_int("MAX_FILES_PER_BATCH", 8)

MAX_FINDINGS_PER_TOOL: int   = _env_int("MAX_FINDINGS_PER_TOOL", 40)
MAX_FINDINGS_PER_BRANCH: int = _env_int("MAX_FINDINGS_PER_BRANCH", 10)



# Event-bus knobs

EVENT_RING_CAP: int  = _env_int("EVENT_RING_CAP", 2000)
EVENT_API_TAIL: int  = _env_int("EVENT_API_TAIL", 800)



# Scoring constants

EXPOSURE_MULTIPLIER: dict[str, float] = {
    "production": 1.00,
    "internal":   0.60,
    "test":       0.15,
    "example":    0.05,
    "doc":        0.03,
}

SEVERITY_DEFAULT_CVSS: dict[str, float] = {
    "critical": 9.0,
    "high":     7.5,
    "medium":   5.0,
    "low":      2.0,
}

GRADE_THRESHOLDS: list[tuple[str, float]] = [
    ("A",  5.0),
    ("B", 12.5),
    ("C", 20.0),
    ("D", 30.0),
    # anything above 30.0 → "F"
]


# AI-scan tool names 

AI_SCAN_TOOL_NAMES: frozenset[str] = frozenset({
    "ai_scan_file",
    "ai_scan_cicd",
    "ai_audit_auth_flow",
})
