"""Agentic repo-intake recon.

Instead of dumping a hardcoded manifest, recon runs its own mini ReAct loop
with `list_repo_files` and `read_file`. The LLM decides which files to
open (typically 5-15) based on what it sees, then returns a structured
`RepoProfile` — including a `hotspot_files` list that the downstream audit
agent uses to target its AI deep-scans.

Recon is scoped: its internal tool-calls stay inside this node. Only the
`repo_profile` plus one context message get forwarded to the outer graph.
"""

from __future__ import annotations

import os
from typing import Any

from langchain_core.messages import HumanMessage

from core.config import RECON_MAX_TOKENS
from agents.prompts.recon_prompt import RECON_PROMPT
from .runtime_log import emit
from .schemas import RepoProfile
from .state import ScanAgentState
from .stream import iter_stream_events
from tools.agent_tools import list_repo_files, read_file, read_files



_recon_agent = None


def _build_recon_agent():
    from agents.llm import get_llm
    from langgraph.prebuilt import create_react_agent

    llm = get_llm(max_tokens=RECON_MAX_TOKENS)

    return create_react_agent(
        model=llm,
        tools=[list_repo_files, read_files, read_file],
        state_schema=ScanAgentState,
        prompt=RECON_PROMPT,
        response_format=RepoProfile,
    )


async def recon_node(state: dict[str, Any]) -> dict[str, Any]:
    """Run the recon sub-agent and surface its RepoProfile to the outer graph."""
    scan_id = state.get("scan_id", "")
    files = state.get("files", {})
    if not files:
        emit(scan_id, "warn", "No files ingested; skipping recon", branch="recon")
        empty = RepoProfile(
            stack="unknown (no files ingested)",
            has_iac=False, has_cicd=False, has_auth=False,
            has_payments=False, has_user_data=False,
            summary="No files were ingested.",
        )
        return {"repo_profile": empty.model_dump(), "messages": []}

    emit(scan_id, "branch_start", f"recon starting on {len(files)} files", branch="recon")

    global _recon_agent
    if _recon_agent is None:
        _recon_agent = _build_recon_agent()

    seen_msg_ids: set[str] = set()
    final_state: dict | None = None

    async for chunk in _recon_agent.astream(
        {
            "messages": [{
                "role": "user",
                "content": (
                    f"Profile this repo. It has {len(files)} files. "
                    "Start by calling list_repo_files, then read strategically."
                ),
            }],
            "files": files,
            "scan_id": scan_id,
        },
        stream_mode="values",
    ):
        if not isinstance(chunk, dict):
            continue
        final_state = chunk
        # Use shared stream helper — no salvage bucket for recon
        iter_stream_events(
            chunk, seen_msg_ids, scan_id, branch="recon",
        )

    result = final_state or {}
    profile = result.get("structured_response")
    if profile is None:
        emit(scan_id, "warn", "recon returned no structured profile", branch="recon")
        fallback = RepoProfile(
            stack="unknown (recon agent did not return a structured profile)",
            has_iac=False, has_cicd=False, has_auth=False,
            has_payments=False, has_user_data=False,
            summary="Recon did not complete; proceeding with blind audit.",
        )
        return {"repo_profile": fallback.model_dump(), "messages": []}

    flags = []
    for f in ("has_iac", "has_cicd", "has_auth", "has_payments", "has_user_data"):
        if getattr(profile, f, False):
            flags.append(f.replace("has_", ""))
    emit(
        scan_id,
        "branch_done",
        f"recon complete: {profile.stack} — flags: {','.join(flags) or 'none'}",
        branch="recon",
    )

    context_msg = HumanMessage(content=(
        "Recon is complete. Here is the RepoProfile:\n\n"
        f"{profile.model_dump_json(indent=2)}"
    ))

    return {
        "repo_profile": profile.model_dump(),
        "messages": [context_msg],
    }
