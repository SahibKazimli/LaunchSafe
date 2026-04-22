"""Centralised configuration for the LaunchSafe agent layer.

Every tunable constant lives here.  Modules import what they need instead
of defining their own defaults.
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


LLM_MODEL: str             = _env_str("LLM_MODEL", "gemini-3.1-pro-preview")

SPEC_RECURSION_LIMIT: int   = _env_int("SPEC_RECURSION_LIMIT", 20)
SPEC_MAX_TOKENS: int        = _env_int("SPEC_MAX_TOKENS", 2048)
# Primary credit knob: agents are instructed to use at most this many tool
# invocations; see spec_react_recursion_limit() for LangGraph *step* count.
SPEC_MAX_TOOL_CALLS: int    = _env_int("SPEC_MAX_TOOL_CALLS", 15)

RECON_MAX_TOKENS: int       = _env_int("RECON_MAX_TOKENS", 1024)
SYNTH_MAX_TOKENS: int       = _env_int("SYNTH_MAX_TOKENS", 1024)
AI_SCAN_MAX_TOKENS: int     = _env_int("AI_SCAN_MAX_TOKENS", 1536)



# Truncation 

MAX_FILE_BYTES: int          = _env_int("MAX_FILE_BYTES", 20_000)
MAX_CICD_BUNDLE_BYTES: int   = _env_int("MAX_CICD_BUNDLE_BYTES", 40_000)
MAX_AUTH_BUNDLE_BYTES: int   = _env_int("MAX_AUTH_BUNDLE_BYTES", 40_000)
MAX_INGEST_FILE_BYTES: int   = _env_int("MAX_INGEST_FILE_BYTES", 200_000)

MAX_BATCH_BYTES: int         = _env_int("MAX_BATCH_BYTES", 120_000)
MAX_FILES_PER_BATCH: int     = _env_int("MAX_FILES_PER_BATCH", 10)

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
