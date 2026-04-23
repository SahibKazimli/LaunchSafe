"""Specialist sub-agents that fan out in parallel after recon.

Each specialist is a `create_react_agent` wrapped in a node function.
The wrapper translates the agent's structured response into the merged
`branch_findings` state field (list-concat reducer in `state.py`), so
all branches can run concurrently without overwriting each other.

Branches:

  general_audit   — always runs; safety net for OWASP, secrets, deps,
                    anything outside the specialist lanes
  payments_audit  — runs if has_payments
  iac_audit       — runs if has_iac
  auth_audit      — runs if has_auth (covers crypto + session + IDOR)
  cicd_audit      — runs if has_cicd

Each specialist gets the full tool set so it can still explore. Its
prompt is what narrows the focus — that lets a specialist follow a thread
into adjacent code without us having to plumb a custom tool list.

This is where I think we can also use that Orchestration layer we talked about to refine agent behavior.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from core.config import (
    SPEC_MAX_TOKENS,
    spec_react_recursion_limit,
)
from agents.prompts.specialist_prompts import (
    AUTH_PROMPT,
    CICD_PROMPT,
    GENERAL_PROMPT,
    IAC_PROMPT,
    PAYMENTS_PROMPT,
    SPECIALIST_KICKOFF,
)
from .runtime_log import emit
from .schemas import Finding
from .state import ScanAgentState
from .stream import collect_salvage, iter_stream_events
from tools.agent_tools import ALL_TOOLS as REGEX_TOOLS
from tools.ai_tools import AI_TOOLS
from tools.budget import scan_budget_guard
from tools.hotspot import select_hotspots

ALL_AGENT_TOOLS = REGEX_TOOLS + AI_TOOLS + [scan_budget_guard, select_hotspots]


class _BranchFindings(BaseModel):
    """What each specialist returns to the synthesizer."""
    findings: list[Finding] = Field(default_factory=list)
    notes: str = Field(
        default="",
        description="ONE sentence on what was checked / what stood out.",
    )



_AGENTS: dict[str, Any] = {}


def _build_specialist(name: str, prompt: str):
    from agents.llm import get_llm
    from langgraph.prebuilt import create_react_agent

    llm = get_llm(max_tokens=SPEC_MAX_TOKENS)

    return create_react_agent(
        model=llm,
        tools=ALL_AGENT_TOOLS,
        state_schema=ScanAgentState,
        prompt=prompt,
        response_format=_BranchFindings,
    )


def _get_agent(name: str, prompt: str):
    if name not in _AGENTS:
        _AGENTS[name] = _build_specialist(name, prompt)
    return _AGENTS[name]


def _make_specialist_node(name: str, prompt: str, kickoff_msg: str):
    """Return an async graph node that runs the named specialist with LIVE
    event streaming and writes its findings into `branch_findings`."""

    async def node(state: dict[str, Any]) -> dict[str, Any]:
        scan_id = state.get("scan_id", "")
        emit(scan_id, "branch_start", f"{name} specialist starting", branch=name)

        agent = _get_agent(name, prompt)

        seen_msg_ids: set[str] = set()
        tool_calls = 0
        final_state: dict | None = None
        salvage_bucket: list[dict] = []
        crashed_with: str | None = None

        try:
            async for chunk in agent.astream(
                {
                    "messages": [{"role": "user", "content": kickoff_msg}],
                    "files": state.get("files", {}),
                    "repo_profile": state.get("repo_profile", {}),
                    "scan_id": scan_id,
                    "target": state.get("target", ""),
                    "branch_findings": [],
                },
                {"recursion_limit": spec_react_recursion_limit()},
                stream_mode="values",
            ):
                if isinstance(chunk, dict):
                    final_state = chunk
                    tool_calls = iter_stream_events(
                        chunk,
                        seen_msg_ids,
                        scan_id,
                        branch=name,
                        tool_calls_so_far=tool_calls,
                        salvage_bucket=salvage_bucket,
                    )
        except Exception as exc:
            crashed_with = str(exc)[:200]
            is_step_limit = (
                "recursion limit" in str(exc).lower()
                or type(exc).__name__ == "GraphRecursionError"
            )
            if is_step_limit and (final_state or {}).get("structured_response") is not None:
                emit(
                    scan_id,
                    "info",
                    f"{name} hit max graph steps but kept a structured result",
                    branch=name,
                )
                crashed_with = None
            else:
                emit(
                    scan_id,
                    "warn",
                    f"{name} crashed: {crashed_with[:140]}",
                    branch=name,
                )

        sr = (final_state or {}).get("structured_response") if not crashed_with else None
        tagged: list[dict] = []

        if sr is not None:
            for f in getattr(sr, "findings", []) or []:
                d = f.model_dump()
                d["_branch"] = name
                tagged.append(d)

        if not tagged and salvage_bucket:
            tagged = collect_salvage(salvage_bucket, branch=name)
            emit(
                scan_id, "info",
                f"{name} salvaged {len(tagged)} finding(s) from intermediate tool calls",
                branch=name,
            )

        emit(
            scan_id, "branch_done",
            f"{name} finished: {len(tagged)} finding(s) from {tool_calls} tool calls"
            + (" (crashed)" if crashed_with else ""),
            branch=name, count=len(tagged), tool_calls=tool_calls,
        )

        if not tagged and crashed_with:
            return {
                "branch_findings": [
                    {"_branch": name, "_error": crashed_with}
                ]
            }
        return {"branch_findings": tagged}

    node.__name__ = f"{name}_node"
    return node



# Public API: one node per specialist + the conditional router

payments_audit_node = _make_specialist_node("payments", PAYMENTS_PROMPT, SPECIALIST_KICKOFF)
iac_audit_node      = _make_specialist_node("iac",      IAC_PROMPT,      SPECIALIST_KICKOFF)
auth_audit_node     = _make_specialist_node("auth",     AUTH_PROMPT,     SPECIALIST_KICKOFF)
cicd_audit_node     = _make_specialist_node("cicd",     CICD_PROMPT,     SPECIALIST_KICKOFF)
general_audit_node  = _make_specialist_node("general",  GENERAL_PROMPT,  SPECIALIST_KICKOFF)


SPECIALIST_NODES: dict[str, Any] = {
    "payments_audit": payments_audit_node,
    "iac_audit":      iac_audit_node,
    "auth_audit":     auth_audit_node,
    "cicd_audit":     cicd_audit_node,
    "general_audit":  general_audit_node,
}


def route_after_recon(state: dict[str, Any]) -> list[str]:
    """Decide which specialist branches run, based on the RepoProfile.

    `general_audit` always runs as a safety net. Others gate on the
    capability flags recon emitted.
    """
    profile = state.get("repo_profile") or {}
    branches = ["general_audit"]
    if profile.get("has_payments"): branches.append("payments_audit")
    if profile.get("has_iac"):      branches.append("iac_audit")
    if profile.get("has_auth"):     branches.append("auth_audit")
    if profile.get("has_cicd"):     branches.append("cicd_audit")
    return branches
