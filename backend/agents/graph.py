"""LaunchSafe agent graph.

A single ReAct agent powered by Claude. It has 8 tools, 6 deterministic
scanners plus `list_repo_files` and `read_file` for repo exploration, and
produces a structured `AuditReport` as its final output.

"""

from __future__ import annotations

import os
from typing import Optional

from pydantic import BaseModel, Field

from .state import ScanAgentState
from .tools.agent_tools import ALL_TOOLS

SYSTEM_PROMPT = """\
You are LaunchSafe, a senior application-security engineer auditing a
startup codebase. Your job is to produce an actionable, prioritised
security report.

Workflow:
1. Call `list_repo_files` first to understand what kind of project this is.
2. Run the relevant scanners. Always run secrets, auth, api, and deps. Run
   cloud only if .tf / .yaml / .yml / .json IaC files exist. Run privacy
   on any app with user data.
3. For findings that look like false positives (EXAMPLE keys, test
   fixtures, docs), you may call `read_file` on the surrounding file to
   confirm. Keep these calls minimal.
4. Once you have enough evidence, STOP calling tools and return your
   final structured AuditReport.

Rules:
- Be concise. Do not repeat tool output verbatim in your messages.
- Prioritise by real-world blast radius, not raw severity. One live AWS
  key > ten hardcoded test secrets.
- The final AuditReport must be valid per the schema. Findings should be
  deduplicated and trimmed to the most important ~25.
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
        description="3-5 imperative sentences: the first things the team should do Monday morning",
    )
    overall_risk: str = Field(description="one of: critical, high, medium, low, minimal")


_compiled = None


def get_agent():
    """Build and cache the compiled LangGraph ReAct agent.

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
    from langgraph.prebuilt import create_react_agent

    model_name = os.environ.get("LAUNCHSAFE_LLM_MODEL", "claude-sonnet-4-5")
    llm = ChatAnthropic(model=model_name, max_tokens=4096, temperature=0)

    _compiled = create_react_agent(
        model=llm,
        tools=ALL_TOOLS,
        state_schema=ScanAgentState,
        prompt=SYSTEM_PROMPT,
        response_format=AuditReport,
    )
    return _compiled
