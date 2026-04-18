"""LaunchSafe agent graph.

Topology:

    START -> recon   (LLM, structured output: RepoProfile)
          -> audit   (ReAct agent with scanner tools + read_file)
          -> END

The audit node is a prebuilt LangGraph ReAct agent. It's embedded as a
sub-graph inside the outer StateGraph so that we can prepend the recon
step and share a single `ScanAgentState` across both.
"""

from __future__ import annotations

import os
from typing import Optional

from pydantic import BaseModel, Field

from .recon import recon_node
from .state import ScanAgentState
from .tools.agent_tools import ALL_TOOLS

AUDIT_SYSTEM_PROMPT = """\
You are LaunchSafe, a senior application-security engineer auditing a
startup codebase. A recon pass has already produced a RepoProfile which
you will receive as the first user message. Use it.

Workflow:
1. Read the RepoProfile in the first message. Skip scanners that are
   irrelevant (e.g. skip scan_cloud_tool if has_iac is false).
2. Always run scan_secrets_tool and scan_auth_tool on any app.
3. Run scan_api_tool if there are route handlers, scan_cloud_tool if
   has_iac, scan_privacy_tool if has_user_data, scan_dependencies_tool
   whenever a manifest is present.
4. For findings in risk_hotspots files, call read_file to confirm true
   positives before including them in the final report.
5. Once you have enough evidence, STOP calling tools and return a
   structured AuditReport.

Rules:
- Be concise. Do not repeat tool output verbatim.
- Prioritise by real-world blast radius, not raw severity. One live AWS
  key > ten hardcoded test secrets.
- Deduplicate findings. Keep the report under ~25 items, most urgent first.
"""


class Finding(BaseModel):
    severity: str = Field(description="one of: critical, high, medium, low")
    module: str = Field(description="one of: secrets, auth, api, cloud, privacy, deps")
    title: str
    location: str
    description: str
    fix: str
    priority: int = Field(description="1 (most urgent) to 5", ge=1, le=5)
    is_true_positive: bool = True
    rationale: Optional[str] = None
    compliance: list[str] = Field(default_factory=list)


class AuditReport(BaseModel):
    summary: str = Field(description="2-4 sentence executive summary")
    findings: list[Finding]
    top_fixes: list[str] = Field(
        description="3-5 imperative sentences: what to do Monday morning",
    )
    overall_risk: str = Field(description="one of: critical, high, medium, low, minimal")


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
        tools=ALL_TOOLS,
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
