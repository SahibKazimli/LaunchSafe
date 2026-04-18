"""LangChain `@tool` wrappers around the deterministic scanners.

The files dict is injected from the agent's state via `InjectedState`, so the
LLM never has to supply the codebase as a tool argument — it just picks
which scanner to run next.

Each tool returns a compact JSON string (capped in size) summarising the
findings. The agent reads the returns, reasons about them, and ultimately
produces a structured `AuditReport`.
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState

from .scanners import (
    scan_api,
    scan_auth,
    scan_cloud,
    scan_dependencies,
    scan_privacy,
    scan_secrets,
)

MAX_FINDINGS_PER_TOOL = 40


def _format(findings: list[dict[str, Any]]) -> str:
    """Cap and serialise findings so one tool call can't blow the context."""
    truncated = findings[:MAX_FINDINGS_PER_TOOL]
    payload = {
        "count": len(findings),
        "returned": len(truncated),
        "findings": truncated,
    }
    return json.dumps(payload, default=str)


@tool
def scan_secrets_tool(state: Annotated[dict, InjectedState]) -> str:
    """FAST TRIAGE (regex-based, no LLM). Grep for known secret patterns
    (AWS keys, Stripe keys, GitHub PATs, private keys, hardcoded DSNs).
    Cheap; run this as a free pre-pass. Follow up with `ai_scan_file` on
    any file where you want deeper analysis."""
    return _format(scan_secrets(state.get("files", {})))


@tool
def scan_auth_tool(state: Annotated[dict, InjectedState]) -> str:
    """FAST TRIAGE (regex-based, no LLM). Grep for obvious auth red flags:
    JWT alg=none, MD5/SHA1, verify=False, DEBUG=True, short SECRET_KEY.
    For real auth-flow analysis use `ai_audit_auth_flow` instead."""
    return _format(scan_auth(state.get("files", {})))


@tool
def scan_api_tool(state: Annotated[dict, InjectedState]) -> str:
    """FAST TRIAGE (regex-based, no LLM). Grep for obvious API issues:
    string-concatenated SQL, wildcard CORS, missing rate-limit imports.
    For injection / IDOR / SSRF reasoning use `ai_scan_file` with the
    relevant focus."""
    return _format(scan_api(state.get("files", {})))


@tool
def scan_cloud_tool(state: Annotated[dict, InjectedState]) -> str:
    """FAST TRIAGE (regex-based, no LLM). Grep IaC files for obvious
    misconfig literals: public-read S3 ACL, publicly_accessible = true,
    0.0.0.0/0, privileged: true. For deeper IaC logic review use
    `ai_scan_file` on the terraform/*.tf files."""
    return _format(scan_cloud(state.get("files", {})))


@tool
def scan_privacy_tool(state: Annotated[dict, InjectedState]) -> str:
    """FAST TRIAGE (regex-based, no LLM). Flag PII-adjacent field names
    (ssn, credit_card, dob) and PII printed to logs. Use `ai_scan_file`
    with focus='general' for real data-handling analysis."""
    return _format(scan_privacy(state.get("files", {})))


@tool
def scan_dependencies_tool(state: Annotated[dict, InjectedState]) -> str:
    """FAST TRIAGE (regex-based, no LLM). Match dependency manifests against
    a small hand-curated CVE list. Useful as a free baseline but the CVE
    list is not exhaustive."""
    return _format(scan_dependencies(state.get("files", {})))


@tool
def list_repo_files(state: Annotated[dict, InjectedState]) -> str:
    """List the paths of all files in the ingested repo along with their
    size in bytes. Useful to decide which scanners are relevant (e.g. skip
    cloud scan if no .tf files)."""
    files = state.get("files", {})
    listing = [{"path": p, "bytes": len(c)} for p, c in files.items()]
    return json.dumps({"count": len(listing), "files": listing[:200]}, default=str)


@tool
def read_file(path: str, state: Annotated[dict, InjectedState]) -> str:
    """Read the full contents of one file from the ingested repo. Use this
    when a scanner finding needs more context (e.g. to confirm a true
    positive). Max 20KB returned; larger files are truncated."""
    content = state.get("files", {}).get(path)
    if content is None:
        return json.dumps({"error": f"file not in repo: {path}"})
    if len(content) > 20_000:
        content = content[:20_000] + "\n...[truncated]"
    return json.dumps({"path": path, "content": content})


ALL_TOOLS = [
    scan_secrets_tool,
    scan_auth_tool,
    scan_api_tool,
    scan_cloud_tool,
    scan_privacy_tool,
    scan_dependencies_tool,
    list_repo_files,
    read_file,
]

SCANNER_TOOL_TO_MODULE = {
    "scan_secrets_tool":      ("secrets", "Secret detection"),
    "scan_auth_tool":         ("auth",    "Auth & access review"),
    "scan_api_tool":          ("api",     "API security review"),
    "scan_cloud_tool":        ("cloud",   "Cloud config audit"),
    "scan_privacy_tool":      ("privacy", "Privacy & compliance"),
    "scan_dependencies_tool": ("deps",    "Dependency scanning"),
}
