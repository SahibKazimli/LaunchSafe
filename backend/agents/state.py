"""Custom state for the LaunchSafe ReAct agent.

Extends LangGraph's built-in `AgentState` (which holds `messages`) with the
repo files the agent audits. Tools receive `files` via `InjectedState` so
the LLM never has to pass the codebase through a tool argument.
"""

from __future__ import annotations

from langgraph.prebuilt.chat_agent_executor import AgentState


class ScanAgentState(AgentState):
    scan_id: str
    target: str
    files: dict[str, str]
