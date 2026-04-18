"""LaunchSafe agent graph.

Topology:

    START
      -> recon   (mini ReAct: list_repo_files + read_file -> RepoProfile)
      -> audit   (ReAct: regex triage + AI deep-scans -> AuditReport)
      -> END

The audit agent has three tiers of tools:

  1. Fast triage (regex, no LLM):       scan_*_tool from agent_tools.py
  2. AI detection (real analysis):      ai_scan_file, ai_scan_cicd, ai_audit_auth_flow
  3. Exploration:                       list_repo_files, read_file

The system prompt steers the LLM to run the fast triage as a free pre-pass
and then spend LLM calls on the hotspots identified during recon.
"""

from __future__ import annotations

import os

from .recon import recon_node
from .schemas import AuditReport
from .state import ScanAgentState
from .tools.agent_tools import ALL_TOOLS as REGEX_TOOLS
from .tools.ai_tools import AI_TOOLS

AUDIT_SYSTEM_PROMPT = """\
You are LaunchSafe, a senior application-security engineer auditing a
startup codebase. A recon pass has already produced a RepoProfile which
you will find in the first user message. USE IT — especially
`hotspot_files` and the capability flags (`has_iac`, `has_cicd`,
`has_auth`, `has_payments`, `has_user_data`).

You have three tiers of tools:

  (1) FAST TRIAGE — regex-based, no LLM cost. Call these first as a free
      pre-pass:
        scan_secrets_tool, scan_auth_tool, scan_api_tool,
        scan_cloud_tool, scan_privacy_tool, scan_dependencies_tool.

  (2) AI DETECTION — real reasoning over code. This is where you find the
      issues regex cannot:
        ai_scan_file(path, focus): deep-scan one file with a focus area
          (auth, injection, crypto, ssrf, authz, cicd, general).
        ai_scan_cicd(): audit all GitHub Actions / Dockerfile / compose
          files for supply-chain risks. Call once if has_cicd is true.
        ai_audit_auth_flow(): audit the complete auth surface across
          multiple files. Call once if has_auth is true.

  (3) EXPLORATION:
        list_repo_files(), read_file(path).

Workflow:
  1. Run the fast triage scanners relevant to the RepoProfile's flags.
  2. For every path in `hotspot_files`, call `ai_scan_file` with the most
     relevant focus. Don't blindly call it with focus='general' — pick
     specifically (a route handler -> focus='injection' + 'authz';
     a crypto util -> 'crypto').
  3. If has_cicd: call `ai_scan_cicd` once.
  4. If has_auth: call `ai_audit_auth_flow` once.
  5. Merge and deduplicate findings from triage + AI. Prefer AI findings
     when they contradict or refine regex hits.
  6. Return the final AuditReport.

Rules:
  - Be concise in your messages; do NOT repeat tool output verbatim.
  - Prioritise by real-world blast radius, not raw severity. One live
    production AWS key > ten hardcoded test fixtures.
  - Drop obvious false positives (EXAMPLE keys, docs, test fixtures) —
    the AI tools already try to, but you are the final filter.
  - Cap the final report at ~25 findings, most urgent first.
"""


_compiled = None


def get_agent():
    """Build and cache the compiled outer graph (recon -> audit).

    Raises RuntimeError if ANTHROPIC_API_KEY is missing at call time.
    """
    global _compiled
    if _compiled is not None:
        return _compiled

    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. Copy .env.example to .env and fill it in."
        )

    from langchain_anthropic import ChatAnthropic
    from langgraph.graph import END, START, StateGraph
    from langgraph.prebuilt import create_react_agent

    model_name = os.environ.get("LAUNCHSAFE_LLM_MODEL", "claude-sonnet-4-5")
    audit_llm = ChatAnthropic(model=model_name, max_tokens=4096, temperature=0)

    audit_agent = create_react_agent(
        model=audit_llm,
        tools=REGEX_TOOLS + AI_TOOLS,
        state_schema=ScanAgentState,
        prompt=AUDIT_SYSTEM_PROMPT,
        response_format=AuditReport,
    )

    outer = StateGraph(ScanAgentState)
    outer.add_node("recon", recon_node)
    outer.add_node("audit", audit_agent)
    outer.add_edge(START, "recon")
    outer.add_edge("recon", "audit")
    outer.add_edge("audit", END)

    _compiled = outer.compile()
    return _compiled
