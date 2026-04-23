"""Fix session LangGraph definition.

Topology:

    START → load_context → plan_fixes → generate_patches
          → review_patches → END

Sequential pipeline (no fan-out yet). Each node reads from and
writes to FixSessionState.  Completely decoupled from the scan graph.
"""

from __future__ import annotations

from .fix_nodes import (
    generate_patches_node,
    load_context_node,
    plan_fixes_node,
    review_patches_node,
)
from .fix_state import FixSessionState


_compiled = None


def get_fix_agent():
    """Build and cache the compiled fix graph."""
    global _compiled
    if _compiled is not None:
        return _compiled

    from langgraph.graph import END, START, StateGraph

    graph = StateGraph(FixSessionState)

    graph.add_node("load_context", load_context_node)
    graph.add_node("plan_fixes", plan_fixes_node)
    graph.add_node("generate_patches", generate_patches_node)
    graph.add_node("review_patches", review_patches_node)

    graph.add_edge(START, "load_context")
    graph.add_edge("load_context", "plan_fixes")
    graph.add_edge("plan_fixes", "generate_patches")
    graph.add_edge("generate_patches", "review_patches")
    graph.add_edge("review_patches", END)

    _compiled = graph.compile()
    return _compiled
