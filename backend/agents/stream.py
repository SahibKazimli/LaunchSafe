"""Shared agent-stream processing utilities.

Consolidates the duplicate stream/event-handling logic that was repeated
Both modules now call
:func:`iter_stream_events` instead of inlining their own message
iteration.

Also provides :func:`parse_ai_tool_findings` (salvage parser) and
:func:`collect_salvage` so error-recovery logic isn't duplicated either.
"""

from __future__ import annotations

import json as _json
from typing import Any

from core.config import AI_SCAN_TOOL_NAMES
from .runtime_log import emit



# AI tool finding salvage

def parse_ai_tool_findings(raw: str) -> list[dict]:
    """Parse the JSON payload an AI deep-scan tool returns into a list of
    raw finding dicts.  Used to salvage findings when the agent crashes
    before producing its final structured_response.
    """
    try:
        data = _json.loads(raw)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    found = data.get("findings")
    if not isinstance(found, list):
        return []
    return [f for f in found if isinstance(f, dict)]


def collect_salvage(
    salvage_bucket: list[dict],
    branch: str,
) -> list[dict]:
    """Dedupe salvaged findings by (title, location) and tag them
    with _branch.  Returns a clean list ready for branch_findings.
    """
    seen_keys: set[tuple] = set()
    out: list[dict] = []
    for f in salvage_bucket:
        key = (f.get("title", ""), f.get("location", ""))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        f.setdefault("_branch", branch)
        out.append(f)
    return out


# Stream event processing

def iter_stream_events(
    chunk: dict[str, Any],
    seen_msg_ids: set[str],
    scan_id: str,
    branch: str,
    tool_calls_so_far: int = 0,
    salvage_bucket: list[dict] | None = None,
) -> int:
    """Process one streamed values-mode chunk and emit live events.

    Parameters
    ----------
    chunk : dict
        A single chunk from agent.astream(..., stream_mode="values").
    seen_msg_ids : set[str]
        Mutable set tracking already-processed message IDs.  Updated
        in-place to prevent duplicate event emission.
    scan_id : str
        Current scan identifier passed through to emit().
    branch : str
        Branch tag for events (e.g. "recon", "auth").
    tool_calls_so_far : int
        Running counter of tool calls in this branch.
    salvage_bucket : list[dict] | None
        If provided, AI deep-scan tool results will be parsed and their
        findings stashed here for crash-recovery. Pass None to skip salvage (e.g. in recon where there are no AI scan tools).

    Returns
    -------
    int
        Updated tool_calls_so_far counter.
    """
    for msg in chunk.get("messages", []) or []:
        msg_id = getattr(msg, "id", None)
        if msg_id and msg_id in seen_msg_ids:
            continue
        if msg_id:
            seen_msg_ids.add(msg_id)
        tool_calls_so_far = _process_message(
            msg, scan_id, branch, tool_calls_so_far, salvage_bucket,
        )
    return tool_calls_so_far


def _process_message(
    msg: Any,
    scan_id: str,
    branch: str,
    tool_calls_so_far: int,
    salvage_bucket: list[dict] | None,
) -> int:
    """Emit events for a single message and optionally salvage findings."""
    msg_type = getattr(msg, "type", None)

    if msg_type == "ai":
        _handle_ai_message(msg, scan_id, branch)
        for tool_call in getattr(msg, "tool_calls", None) or []:
            tool_calls_so_far += 1
            tool_call_name = tool_call.get("name", "?") if isinstance(tool_call, dict) else "?"
            tool_call_args = tool_call.get("args") or {} if isinstance(tool_call, dict) else {}
            arg_parts = []
            for key, value in list(tool_call_args.items())[:2]:
                string_value = str(value)
                if len(string_value) > 50:
                    string_value = string_value[:47] + "…"
                arg_parts.append(f"{key}={string_value}")
            emit(scan_id, "call", f"{tool_call_name}({', '.join(arg_parts)})", branch=branch)

    elif msg_type == "tool":
        tool_name = getattr(msg, "name", "?")
        content = getattr(msg, "content", "") or ""
        size = len(content) if isinstance(content, str) else 0
        added = 0
        if (
            salvage_bucket is not None
            and tool_name in AI_SCAN_TOOL_NAMES
            and isinstance(content, str)
        ):
            for f in parse_ai_tool_findings(content):
                f.setdefault("_branch", branch)
                salvage_bucket.append(f)
                added += 1
        suffix = f", +{added} salvaged" if added else ""
        emit(scan_id, "result", f"{tool_name} → {size}B{suffix}", branch=branch)

    return tool_calls_so_far


def _handle_ai_message(msg: Any, scan_id: str, branch: str) -> None:
    """Emit ``think`` events for AI message content blocks."""
    content = getattr(msg, "content", "")
    if isinstance(content, str) and content.strip():
        emit(scan_id, "think", content.strip(), branch=branch)
    elif isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                txt = (block.get("text") or "").strip()
                if txt:
                    emit(scan_id, "think", txt, branch=branch)
