"""Custom state for the LaunchSafe agent graph.

Extends LangGraph's built-in `AgentState` (which holds `messages`) with the
repo files the agent audits. Tools receive `files` via `InjectedState` so
the LLM never has to pass the codebase through a tool argument.

`branch_findings` uses a list-concat reducer so multiple specialist agents
running in parallel can each append their findings without overwriting
each other. The synthesize node reads the merged list at the end.
"""

from __future__ import annotations

from operator import add
from typing import Annotated, Any

from langgraph.prebuilt.chat_agent_executor import AgentState


class ScanAgentState(AgentState):
    scan_id: str
    target: str
    files: dict[str, str]
    repo_profile: dict
    structured_response: Any
    branch_findings: Annotated[list[dict], add]
