"""AI-powered scanning tools.

Each tool spawns a structured-output Claude call over actual file contents.
No pattern matching — the LLM reasons over the code. These are the real
detection layer; the regex tools in `agent_tools.py` are only a cheap
triage pre-pass.

Each tool returns a JSON-serialised `_FileFindings` object. The outer
ReAct agent reads it, decides whether to dig further, and folds true
positives into the final `AuditReport`.
"""

from __future__ import annotations

import json
from typing import Annotated

from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState
from pydantic import BaseModel, Field

from agents.prompts.ai_scan_prompts import (
    AI_AUDIT_AUTH_FLOW_SYSTEM,
    AI_SCAN_CICD_SYSTEM,
    build_ai_scan_file_system,
    format_ai_scan_file_user,
)
from agents.schemas import Finding
from core.config import (
    AI_SCAN_MAX_TOKENS,
    MAX_AUTH_BUNDLE_BYTES,
    MAX_CICD_BUNDLE_BYTES,
    MAX_FILE_BYTES,
)


class _FileFindings(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    notes: str = Field(default="", description="short auditor notes; empty if nothing interesting")


def _get_llm():
    from agents.llm import get_llm
    return get_llm(max_tokens=AI_SCAN_MAX_TOKENS)


def _truncate(content: str, limit: int) -> str:
    if len(content) <= limit:
        return content
    return content[:limit] + "\n...[truncated]"


def _empty(notes: str) -> str:
    return json.dumps({"findings": [], "notes": notes})


@tool
def ai_scan_file(
    path: str,
    focus: str,
    state: Annotated[dict, InjectedState],
) -> str:
    """AI-reads one file and returns structured vulnerability findings.
    No regex — Claude reasons over the actual code.

    `focus` must be one of: auth, injection, crypto, ssrf, authz, cicd, general.

    Use this on hotspot files identified in the RepoProfile. Call once per
    (file, focus) pair. Prefer this tool over the regex scanners for
    high-value files.
    """
    files = state.get("files", {})
    content = files.get(path)
    if content is None:
        return _empty(f"file not found: {path}")

    snippet = _truncate(content, MAX_FILE_BYTES)

    system = build_ai_scan_file_system(focus)
    user = format_ai_scan_file_user(path, snippet)

    structured = _get_llm().with_structured_output(_FileFindings)
    try:
        result: _FileFindings = structured.invoke(
            [{"role": "system", "content": system},
             {"role": "user", "content": user}]
        )
        return result.model_dump_json()
    except Exception as exc:  # noqa: BLE001
        return _empty(f"ai_scan_file failed: {exc!s}")


@tool
def ai_scan_cicd(state: Annotated[dict, InjectedState]) -> str:
    """AI-audit of CI/CD configuration: GitHub Actions workflows
    (.github/workflows/*.yml), Dockerfile, docker-compose.*.

    Catches: pull_request_target + untrusted checkout, unpinned actions,
    ${{ github.event.* }} script injection, secret exposure, over-broad
    permissions, Dockerfile running as root, unsafe base images, privileged
    compose services.
    """
    files = state.get("files", {})
    cicd_files = {}
    for path, content in files.items():
        if (
            path.startswith(".github/workflows/")
            or path == "Dockerfile"
            or path.endswith("/Dockerfile")
            or path.rsplit("/", 1)[-1] in ("docker-compose.yml", "docker-compose.yaml")
        ):
            cicd_files[path] = content
    if not cicd_files:
        return _empty("No CI/CD configuration files found.")

    bundle_parts: list[str] = []
    used = 0
    for path, content in cicd_files.items():
        section = f"### {path}\n```\n{_truncate(content, 8000)}\n```"
        if used + len(section) > MAX_CICD_BUNDLE_BYTES:
            break
        bundle_parts.append(section)
        used += len(section)
    bundle = "\n\n".join(bundle_parts)

    structured = _get_llm().with_structured_output(_FileFindings)
    try:
        result: _FileFindings = structured.invoke(
            [{"role": "system", "content": AI_SCAN_CICD_SYSTEM},
             {"role": "user", "content": bundle}]
        )
        return result.model_dump_json()
    except Exception as exc:  # noqa: BLE001
        return _empty(f"ai_scan_cicd failed: {exc!s}")


@tool
def ai_audit_auth_flow(state: Annotated[dict, InjectedState]) -> str:
    """AI-audit of the complete authentication flow across multiple files.
    Reads all auth-adjacent files together (not one at a time) so it can
    reason about the whole flow — e.g. session invalidated on logout but
    token still valid in another file.
    """
    files = state.get("files", {})
    keywords = ("auth", "login", "logout", "session", "jwt", "oauth",
                "password", "token", "middleware", "identity", "account")
    auth_files = {
        path: content for path, content in files.items()
        if any(kw in path.lower() for kw in keywords)
    }
    if not auth_files:
        return _empty("No auth-related files identified by path.")

    bundle_parts: list[str] = []
    used = 0
    for path, content in auth_files.items():
        section = f"### {path}\n```\n{_truncate(content, 6000)}\n```"
        if used + len(section) > MAX_AUTH_BUNDLE_BYTES:
            break
        bundle_parts.append(section)
        used += len(section)
    bundle = "\n\n".join(bundle_parts)

    structured = _get_llm().with_structured_output(_FileFindings)
    try:
        result: _FileFindings = structured.invoke(
            [{"role": "system", "content": AI_AUDIT_AUTH_FLOW_SYSTEM},
             {"role": "user", "content": bundle}]
        )
        return result.model_dump_json()
    except Exception as exc:
        return _empty(f"ai_audit_auth_flow failed: {exc!s}")


AI_TOOLS = [ai_scan_file, ai_scan_cicd, ai_audit_auth_flow]

AI_TOOL_TO_MODULE = {
    "ai_scan_file":       ("ai_deep", "AI deep-file scan"),
    "ai_scan_cicd":       ("ai_cicd", "AI CI/CD audit"),
    "ai_audit_auth_flow": ("ai_auth", "AI auth-flow audit"),
}
