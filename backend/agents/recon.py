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

from .schemas import RepoProfile
from .state import ScanAgentState
from .tools.agent_tools import list_repo_files, read_file

RECON_PROMPT = """\
You are a senior security auditor doing an initial reconnaissance pass on
a codebase. You must produce a structured RepoProfile.

You have two tools:
  - list_repo_files(): returns every file path and its byte size
  - read_file(path): returns the full contents of one file (<=20KB)

Workflow:
1. Call list_repo_files FIRST to see the full tree.
2. Based on what you see, read 5-15 files of your own choosing. Prioritise:
   - READMEs (to understand what the app does)
   - Dependency manifests (package.json, requirements.txt, pyproject.toml)
   - Main entry points (main.py, app.py, server.ts, index.ts)
   - Auth modules (anything with auth/session/jwt/oauth in the path)
   - Route/controller files
   - IaC (Terraform, k8s, Pulumi) and CI/CD workflows (.github/workflows/)
   - Dockerfile / docker-compose
3. STOP reading when you have enough context — don't read every file.
4. Return the RepoProfile. Set `hotspot_files` to the paths most worth
   deep-scanning in the next phase, ordered by scrutiny priority.

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
        tools=[list_repo_files, read_file],
        state_schema=ScanAgentState,
        prompt=RECON_PROMPT,
        response_format=RepoProfile,
    )


def recon_node(state: dict[str, Any]) -> dict[str, Any]:
    """Run the recon sub-agent and surface its RepoProfile to the outer graph."""
    files = state.get("files", {})
    if not files:
        empty = RepoProfile(
            stack="unknown (no files ingested)",
            has_iac=False, has_cicd=False, has_auth=False,
            has_payments=False, has_user_data=False,
            summary="No files were ingested.",
        )
        return {"repo_profile": empty.model_dump(), "messages": []}

    global _recon_agent
    if _recon_agent is None:
        _recon_agent = _build_recon_agent()

    result = _recon_agent.invoke({
        "messages": [{
            "role": "user",
            "content": (
                f"Profile this repo. It has {len(files)} files. "
                "Start by calling list_repo_files, then read strategically."
            ),
        }],
        "files": files,
    })

    profile = result.get("structured_response")
    if profile is None:
        fallback = RepoProfile(
            stack="unknown (recon agent did not return a structured profile)",
            has_iac=False, has_cicd=False, has_auth=False,
            has_payments=False, has_user_data=False,
            summary="Recon did not complete; proceeding with blind audit.",
        )
        return {"repo_profile": fallback.model_dump(), "messages": []}

    context_msg = HumanMessage(content=(
        "Recon is complete. Here is the RepoProfile:\n\n"
        f"{profile.model_dump_json(indent=2)}\n\n"
        "Use `hotspot_files` as your deep-scan targets. Use AI tools "
        "(ai_scan_file, ai_scan_cicd, ai_audit_auth_flow) for real "
        "vulnerability hunting. You may also call the fast regex-triage "
        "tools (scan_secrets_tool etc.) as a cheap first pass. Now produce "
        "the final AuditReport."
    ))

    return {
        "repo_profile": profile.model_dump(),
        "messages": [context_msg],
    }
