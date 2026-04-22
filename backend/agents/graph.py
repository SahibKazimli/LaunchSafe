"""LaunchSafe agent graph.

Topology:

    START
      -> recon
            (mini ReAct: list_repo_files + read_files -> RepoProfile)
      -> conditional fan-out (route_after_recon, based on RepoProfile flags)
            general_audit         (always)
            payments_audit        (if has_payments)
            iac_audit             (if has_iac)
            auth_audit            (if has_auth)
            cicd_audit            (if has_cicd)
      -> synthesize
            (dedupe + LLM exec summary -> AuditReport)
      -> END

All specialist branches run concurrently. Each one is a `create_react_agent`
with the FULL tool set but a focused prompt that defines its lane.
Findings from every branch are list-concat-merged into `branch_findings`
(see `state.py`), then the synthesize node dedupes and writes the final
`structured_response` (an `AuditReport`) — which is what the FastAPI
runner reads when the graph completes.
"""

from __future__ import annotations

import os

from .recon import recon_node
from .specialists import SPECIALIST_NODES, route_after_recon
from .state import ScanAgentState
from .synthesize import synthesize_node


_compiled = None


def get_agent():
    """Build and cache the compiled outer graph.

    Raises RuntimeError if no LLM API key is set at call time.
    """
    global _compiled
    if _compiled is not None:
        return _compiled

    if not os.environ.get("GEMINI_API_KEY") and not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError(
            "No LLM API key set. Add GEMINI_API_KEY or ANTHROPIC_API_KEY to .env."
        )

    from langgraph.graph import END, START, StateGraph

    outer = StateGraph(ScanAgentState)
    outer.add_node("recon", recon_node)
    for name, node in SPECIALIST_NODES.items():
        outer.add_node(name, node)
    outer.add_node("synthesize", synthesize_node)

    outer.add_edge(START, "recon")
    outer.add_conditional_edges(
        "recon",
        route_after_recon,
        list(SPECIALIST_NODES.keys()),
    )
    for name in SPECIALIST_NODES:
        outer.add_edge(name, "synthesize")
    outer.add_edge("synthesize", END)

    _compiled = outer.compile()
    return _compiled
