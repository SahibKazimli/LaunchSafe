"""Scan budget guard tool.

Gives specialist agents runtime visibility into their tool-call budget.
Instead of relying on the LLM to count its own tool calls, this tool reads the message history from injected
state and returns a ``{used, remaining, budget, should_stop}``
payload.

The specialist prompt instructs agents to call this periodically and to
stop scanning when ``should_stop`` is True.
"""

from __future__ import annotations

import json
from typing import Annotated

from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState

from core.config import SPEC_MAX_TOOL_CALLS


def _count_tool_calls(messages: list) -> int:
    """Count completed tool calls by looking at ToolMessage instances
    in the message history. """
    count = 0
    for msg in messages:
        if getattr(msg, "type", None) == "tool":
            count += 1
    return count


@tool
def scan_budget_guard(state: Annotated[dict, InjectedState]) -> str:
    """Check how many tool calls you have used and how many remain.

    Call this before planning your next batch of tool calls. If ``should_stop`` is true, you MUST return your findings immediately on your next response, do not call any more tools.

    Returns JSON: {used, remaining, budget, should_stop, message}.
    """
    messages = state.get("messages", [])
    used = _count_tool_calls(messages)
    budget = SPEC_MAX_TOOL_CALLS
    remaining = max(0, budget - used)
    should_stop = remaining <= 1

    if should_stop:
        message = (
            f"Budget exhausted: {used}/{budget} tool calls used. "
            "Return your _BranchFindings NOW with whatever you have. "
            "Note unfinished work in the `notes` field."
        )
    elif remaining <= 3:
        message = (
            f"Budget low: {used}/{budget} used, {remaining} remaining. "
            "Wrap up — use remaining calls on highest-value targets only."
        )
    else:
        message = f"Budget OK: {used}/{budget} used, {remaining} remaining."

    return json.dumps({
        "used": used,
        "remaining": remaining,
        "budget": budget,
        "should_stop": should_stop,
        "message": message,
    })
