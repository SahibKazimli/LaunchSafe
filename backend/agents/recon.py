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

from .runtime_log import emit
from .schemas import RepoProfile
from .state import ScanAgentState
from .tools.agent_tools import list_repo_files, read_file, read_files

RECON_PROMPT = """\
You are a senior security auditor doing an initial reconnaissance pass on
a codebase. You must produce a structured RepoProfile.

You have three tools:
  - list_repo_files(): returns every file path and its byte size
  - read_files(paths): BATCH-read up to 10 files at once. PREFER THIS.
  - read_file(path): read one file (only when exploring adaptively)

Workflow:
1. Call list_repo_files FIRST to see the full tree.
2. In ONE call to `read_files`, batch-fetch the key files. Prioritise:
   - READMEs (to understand what the app does)
   - Dependency manifests (package.json, requirements.txt, pyproject.toml)
   - Main entry points (main.py, app.py, server.ts, index.ts)
   - Auth modules (anything with auth/session/jwt/oauth in the path)
   - Route/controller files
   - IaC (Terraform, k8s, Pulumi) and CI/CD workflows (.github/workflows/)
   - Dockerfile / docker-compose
3. If you need a couple more files AFTER seeing the first batch, call
   `read_files` again (batch) or `read_file` (single, for adaptive picks).
4. STOP reading when you have enough context — don't read every file.
5. Return the RepoProfile. Set `hotspot_files` to the paths most worth
   deep-scanning in the next phase, ordered by scrutiny priority.

Each tool call costs ~2-4 seconds of inference round-trip, so batching is
MUCH faster than a sequence of single reads. Target 2-3 total tool calls
before returning the profile.

Do NOT attempt to find specific vulnerabilities yet. Recon is about
understanding the system and identifying where to look hardest.
"""


_recon_agent = None


def _build_recon_agent():
    from langchain_anthropic import ChatAnthropic
    from langgraph.prebuilt import create_react_agent

    model_name = os.environ.get("LAUNCHSAFE_LLM_MODEL", "claude-sonnet-4-5")
    llm = ChatAnthropic(model=model_name, max_tokens=2048, temperature=0)

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

    result = await _recon_agent.ainvoke({
        "messages": [{
            "role": "user",
            "content": (
                f"Profile this repo. It has {len(files)} files. "
                "Start by calling list_repo_files, then read strategically."
            ),
        }],
        "files": files,
    })

    for msg in result.get("messages", []) or []:
        msg_type = getattr(msg, "type", None)
        if msg_type == "ai":
            for tc in getattr(msg, "tool_calls", None) or []:
                tc_name = tc.get("name", "?") if isinstance(tc, dict) else "?"
                emit(scan_id, "call", f"{tc_name}(...)", branch="recon")
        elif msg_type == "tool":
            tool_name = getattr(msg, "name", "?")
            content = getattr(msg, "content", "") or ""
            size = len(content) if isinstance(content, str) else 0
            emit(scan_id, "result", f"{tool_name} → {size}B", branch="recon")

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
