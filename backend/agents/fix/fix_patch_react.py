"""ReAct subgraph for fix step 2: tool-grounded patch edits."""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.errors import GraphRecursionError
from langgraph.prebuilt import InjectedState, create_react_agent
from typing_extensions import Annotated

# Returned as ``diagnostic`` when the subgraph hits ``recursion_limit`` (expected; legacy fallback).
REACT_DIAG_RECURSION_LIMIT = "recursion_limit"

from agents.llm import get_llm
from agents.prompts.fix_prompts import PATCH_REACT_EDIT_SYSTEM
from core.config import (
    FIX_PATCH_LLM_TEMPERATURE,
    FIX_PATCH_MAX_TOKENS,
    FIX_PATCH_REACT_BATCH_BYTES,
    FIX_PATCH_REACT_READ_CAP,
    fix_patch_react_recursion_limit,
)
from core.finding_files import find_file_content, resolve_path_to_canonical_key
from tools.agent_tools import list_repo_files

from .fix_state import FixPatchReactState, PatchEditBundle, PatchEditRow

MAX_FIX_READ_BATCH = 10

_fix_patch_react_agent: Any | None = None


def _tool_call_name(tool_call: Any) -> str:
    if isinstance(tool_call, dict):
        return str(tool_call.get("name") or "")
    return str(getattr(tool_call, "name", "") or "")


def _tool_call_args(tool_call: Any) -> dict[str, Any]:
    if isinstance(tool_call, dict):
        raw = tool_call.get("args")
    else:
        raw = getattr(tool_call, "args", None)
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _record_read_from_tool_pair(
    tool_call: Any,
    tool_message: ToolMessage,
    files: dict[str, str],
    keys: set[str],
) -> None:
    name = _tool_call_name(tool_call)
    try:
        payload = (
            json.loads(tool_message.content) if isinstance(tool_message.content, str) else {}
        )
    except json.JSONDecodeError:
        return
    if not isinstance(payload, dict) or payload.get("error"):
        return

    if name == "fix_read_file":
        path_hint = _tool_call_args(tool_call).get("path") or payload.get("path") or ""
        file_key, _ = find_file_content(str(path_hint), files)
        if file_key:
            keys.add(file_key)
        return

    if name == "fix_read_files":
        for file_record in payload.get("files") or []:
            if not isinstance(file_record, dict):
                continue
            nested_path = file_record.get("path") or ""
            file_key, _ = find_file_content(str(nested_path), files)
            if file_key:
                keys.add(file_key)


def collect_fix_react_canonical_keys_read(messages: list[Any], files: dict[str, str]) -> set[str]:
    """Canonical repo keys the agent successfully loaded via fix_read_* tools."""
    keys: set[str] = set()
    i = 0
    while i < len(messages):
        message = messages[i]
        if isinstance(message, AIMessage) and message.tool_calls:
            tool_call_count = len(message.tool_calls)
            for tool_call_index, tool_call in enumerate(message.tool_calls):
                message_index = i + 1 + tool_call_index
                if message_index >= len(messages):
                    break
                tool_message = messages[message_index]
                if isinstance(tool_message, ToolMessage):
                    _record_read_from_tool_pair(tool_call, tool_message, files, keys)
            i += 1 + tool_call_count
            continue
        i += 1
    return keys


def edits_tool_grounding_ok(
    validated_pairs: list[tuple[str, str]],
    edits: list[PatchEditRow],
    keys_read: set[str],
    files: dict[str, str],
) -> tuple[bool, str]:
    """True when every edited locate target's file was read via fix_read_* tools."""
    required: set[str] = set()
    for edit in edits:
        pair_index = edit.index
        if not isinstance(pair_index, int) or pair_index < 0 or pair_index >= len(validated_pairs):
            continue
        path = validated_pairs[pair_index][0]
        file_key = resolve_path_to_canonical_key(path, files)
        if file_key:
            required.add(file_key)
    if not required:
        return True, ""
    missing = sorted(required - keys_read)
    if not missing:
        return True, ""
    return False, "Paths not read via tools: " + ", ".join(missing[:12])


@tool
def grep_repo(
    substring: str,
    state: Annotated[dict, InjectedState],
    case_insensitive: bool = False,
    max_hits: int = 40,
) -> str:
    """Search ingested files for a literal substring (not regex). Returns compact hits."""
    needle = (substring or "").strip()
    if len(needle) < 2:
        return json.dumps({"error": "substring must be at least 2 characters"})
    files = state.get("files", {})
    max_hits = max(1, min(int(max_hits), 80))
    hits: list[dict[str, Any]] = []
    n = 0
    for path, content in files.items():
        hay = content if not case_insensitive else content.lower()
        needle_lower = needle if not case_insensitive else needle.lower()
        if needle_lower not in hay:
            continue
        # first line match
        for li, line in enumerate(content.splitlines(), start=1):
            line_lower = line if not case_insensitive else line.lower()
            if needle_lower in line_lower:
                excerpt = line_lower.strip()
                if len(excerpt) > 200:
                    excerpt = excerpt[:200] + "…"
                hits.append({"path": path, "line": li, "excerpt": excerpt})
                n += 1
                break
        if n >= max_hits:
            break
    return json.dumps({"substring": substring, "hits": hits, "count": len(hits)})


@tool
def fix_read_file(path: str, state: Annotated[dict, InjectedState]) -> str:
    """Read one file from the ingested snapshot (paths may be suffix-matched like scan locations)."""
    files = state.get("files", {})
    file_key, content = find_file_content(path, files)
    if not content:
        return json.dumps({"error": f"file not in repo: {path}"})
    cap = FIX_PATCH_REACT_READ_CAP
    truncated = len(content) > cap
    body = content[:cap] + ("\n...[truncated]" if truncated else "")
    return json.dumps({"path": file_key, "content": body, "truncated": truncated})


@tool
def fix_read_files(paths: list[str], state: Annotated[dict, InjectedState]) -> str:
    """Batch-read files from the ingested snapshot (up to 10 paths per call)."""
    repo = state.get("files", {})
    out: list[dict[str, Any]] = []
    skipped: list[str] = []
    total = 0
    cap = FIX_PATCH_REACT_READ_CAP
    budget = FIX_PATCH_REACT_BATCH_BYTES

    for path in paths[:MAX_FIX_READ_BATCH]:
        file_key, content = find_file_content(path, repo)
        if not content:
            skipped.append(path)
            continue
        truncated = len(content) > cap
        body = content[:cap] + ("\n...[truncated]" if truncated else "")
        chunk_len = len(body)
        if total + chunk_len > budget:
            skipped.append(path)
            continue
        total += chunk_len
        out.append({"path": file_key, "content": body, "truncated": truncated})

    for path in paths[MAX_FIX_READ_BATCH:]:
        skipped.append(path)

    return json.dumps({"files": out, "skipped": skipped})


FIX_PATCH_REACT_TOOLS = [
    list_repo_files,
    grep_repo,
    fix_read_file,
    fix_read_files,
]


def _build_fix_patch_react_agent() -> Any:
    llm = get_llm(max_tokens=FIX_PATCH_MAX_TOKENS, temperature=FIX_PATCH_LLM_TEMPERATURE)
    return create_react_agent(
        model=llm,
        tools=FIX_PATCH_REACT_TOOLS,
        state_schema=FixPatchReactState,
        prompt=PATCH_REACT_EDIT_SYSTEM,
        response_format=PatchEditBundle,
    )


def get_fix_patch_react_agent() -> Any:
    global _fix_patch_react_agent
    if _fix_patch_react_agent is None:
        _fix_patch_react_agent = _build_fix_patch_react_agent()
    return _fix_patch_react_agent


async def run_fix_patch_react_edit(
    user_message: str,
    files: dict[str, str],
) -> tuple[PatchEditBundle | None, set[str], str]:
    """Run the ReAct patch agent; return (bundle, canonical keys read, diagnostic).

    ``diagnostic`` is ``REACT_DIAG_RECURSION_LIMIT`` when the LangGraph step cap is hit —
    a normal outcome when the model needs more tool rounds than configured; callers should
    fall back to excerpt-based edit without treating it as a hard failure.
    """
    agent = get_fix_patch_react_agent()
    try:
        final = await agent.ainvoke(
            {
                "messages": [HumanMessage(content=user_message)],
                "files": files,
            },
            config={"recursion_limit": fix_patch_react_recursion_limit()},
        )
    except GraphRecursionError:
        return None, set(), REACT_DIAG_RECURSION_LIMIT
    except Exception as exc:  # noqa: BLE001
        return None, set(), f"ReAct patch agent failed: {exc!s:.200}"

    final_messages = final.get("messages") or []
    keys = collect_fix_react_canonical_keys_read(final_messages, files)
    structured = final.get("structured_response")
    if structured is None:
        return None, keys, "ReAct patch agent returned no structured PatchEditBundle"
    if isinstance(structured, PatchEditBundle):
        return structured, keys, ""
    if isinstance(structured, dict):
        try:
            return PatchEditBundle.model_validate(structured), keys, ""
        except Exception as exc:  # noqa: BLE001
            return None, keys, f"Invalid PatchEditBundle: {exc!s:.120}"
    return None, keys, "Unexpected structured_response type"
