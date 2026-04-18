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
    """Scan the codebase for leaked secrets (API keys, tokens, private keys,
    hardcoded passwords, DSNs with credentials). Returns a JSON list of
    findings with severity, location, and a redacted description.
    Call this first on any audit."""
    return _format(scan_secrets(state.get("files", {})))


@tool
def scan_auth_tool(state: Annotated[dict, InjectedState]) -> str:
    """Scan for authentication and access-control issues: JWT with alg=none,
    weak hashing (MD5/SHA1), disabled TLS verification, debug mode on, and
    short SECRET_KEY values."""
    return _format(scan_auth(state.get("files", {})))


@tool
def scan_api_tool(state: Annotated[dict, InjectedState]) -> str:
    """Scan for API security issues: string-concatenated SQL queries (SQLi),
    wildcard CORS, and missing rate limiting on route handlers."""
    return _format(scan_api(state.get("files", {})))


@tool
def scan_cloud_tool(state: Annotated[dict, InjectedState]) -> str:
    """Scan infrastructure-as-code (Terraform/YAML/JSON) for cloud
    misconfiguration: public S3 ACLs, publicly-accessible RDS, IAM wildcard
    actions, 0.0.0.0/0 ingress, privileged containers."""
    return _format(scan_cloud(state.get("files", {})))


@tool
def scan_privacy_tool(state: Annotated[dict, InjectedState]) -> str:
    """Scan for GDPR/CCPA privacy issues: PII field names (ssn, credit_card,
    dob), PII written to logs, and missing privacy policy file."""
    return _format(scan_privacy(state.get("files", {})))


@tool
def scan_dependencies_tool(state: Annotated[dict, InjectedState]) -> str:
    """Scan dependency manifests (package.json, requirements.txt, Pipfile,
    pyproject.toml) for packages with known CVEs."""
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
