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
import os
from typing import Annotated

from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState
from pydantic import BaseModel, Field

from ..schemas import (
    COMPLIANCE_INSTRUCTIONS,
    CVSS_AND_EXPOSURE_RUBRIC,
    SEVERITY_RUBRIC,
    Finding,
)

MAX_FILE_BYTES = 20_000
MAX_CICD_BUNDLE_BYTES = 40_000
MAX_AUTH_BUNDLE_BYTES = 40_000


class _FileFindings(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    notes: str = Field(default="", description="short auditor notes; empty if nothing interesting")


FOCUS_INSTRUCTIONS = {
    "auth": (
        "Focus on authentication & session: JWT validation (alg confusion, "
        "missing aud/iss, long expiries), OAuth state/PKCE, cookie flags "
        "(Secure, HttpOnly, SameSite), session fixation/invalidation, "
        "password reset token reuse, timing-unsafe credential compare, MFA bypass."
    ),
    "injection": (
        "Focus on injection: SQL (parameterised vs concat), NoSQL operators "
        "in user input, command injection via shell=True / exec, LDAP, "
        "XPath, template injection, prompt injection in LLM calls."
    ),
    "crypto": (
        "Focus on cryptographic misuse: weak algorithms (MD5, SHA1, DES), "
        "ECB mode, reused/static IVs, weak PRNG for security tokens "
        "(random vs secrets.token_bytes), timing-unsafe comparisons "
        "(== vs hmac.compare_digest), hardcoded keys, missing salt."
    ),
    "ssrf": (
        "Focus on SSRF, path traversal, XXE, open redirects, unsafe URL "
        "parsing, server-side fetches with user-supplied URLs, unrestricted "
        "file upload paths."
    ),
    "authz": (
        "Focus on broken object-level authorization (IDOR): does every "
        "handler verify the current user owns / can access the requested "
        "resource? Missing authorization checks, privilege escalation, "
        "role confusion, mass-assignment of protected fields."
    ),
    "cicd": (
        "Focus on CI/CD supply-chain risks for this file: pull_request_target "
        "+ untrusted checkout, unpinned actions (@v2 or @main instead of "
        "SHA), script injection via ${{ github.event.* }} in run:, secret "
        "echo/log leakage, overly broad permissions, self-hosted runners "
        "on public triggers, Dockerfile running as root, ADD <url>, "
        ":latest base images."
    ),
    "general": (
        "Look for any security vulnerability: the categories above and "
        "anything else genuinely exploitable. Be precise, not paranoid."
    ),
}


def _get_llm():
    from langchain_anthropic import ChatAnthropic

    model = os.environ.get("LAUNCHSAFE_LLM_MODEL", "claude-sonnet-4-5")
    return ChatAnthropic(model=model, max_tokens=3072, temperature=0)


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

    instruction = FOCUS_INSTRUCTIONS.get(focus, FOCUS_INSTRUCTIONS["general"])
    snippet = _truncate(content, MAX_FILE_BYTES)

    system = (
        "You are a senior application-security engineer. "
        f"{instruction}\n\n"
        f"{SEVERITY_RUBRIC}\n"
        f"{CVSS_AND_EXPOSURE_RUBRIC}\n"
        f"{COMPLIANCE_INSTRUCTIONS}\n"
        "Rules:\n"
        "- Only report real, exploitable issues you can justify from the code.\n"
        "- Do NOT invent vulnerabilities. If the file is clean for this focus, "
        "return empty findings and a short note.\n"
        "- For each finding, set `location` to `path:line` where line is the "
        "line number of the issue in the provided file.\n"
        "- Set `module` to the most specific tag (authz, crypto, injection, "
        "ssrf, cicd, etc.). `priority` 1 = urgent, 5 = minor.\n"
        "- Apply the SEVERITY DEFINITIONS above strictly — do not inflate."
    )
    user = f"File: {path}\n\n```\n{snippet}\n```"

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
    for p, c in files.items():
        if (
            p.startswith(".github/workflows/")
            or p == "Dockerfile"
            or p.endswith("/Dockerfile")
            or p.rsplit("/", 1)[-1] in ("docker-compose.yml", "docker-compose.yaml")
        ):
            cicd_files[p] = c
    if not cicd_files:
        return _empty("No CI/CD configuration files found.")

    bundle_parts: list[str] = []
    used = 0
    for p, c in cicd_files.items():
        section = f"### {p}\n```\n{_truncate(c, 8000)}\n```"
        if used + len(section) > MAX_CICD_BUNDLE_BYTES:
            break
        bundle_parts.append(section)
        used += len(section)
    bundle = "\n\n".join(bundle_parts)

    system = (
        "You are a DevSecOps expert auditing CI/CD configuration.\n"
        f"{SEVERITY_RUBRIC}\n"
        f"{CVSS_AND_EXPOSURE_RUBRIC}\n"
        f"{COMPLIANCE_INSTRUCTIONS}\n"
        "Look for:\n"
        "1. pull_request_target + actions/checkout on PR ref (code execution on untrusted input).\n"
        "2. Actions pinned by tag/branch (@v2, @main) rather than SHA.\n"
        "3. ${{ github.event.* }} or ${{ github.head_ref }} used in `run:` "
        "(script injection — always assign to env first).\n"
        "4. `echo \"${{ secrets.* }}\"`, secrets printed to logs.\n"
        "5. `permissions: write-all`, or no `permissions:` on sensitive jobs.\n"
        "6. Self-hosted runners triggered by public events.\n"
        "7. Dockerfile: no USER directive, running as root, ADD <url>, "
        "`:latest` base images, `apt-get` without cleanup.\n"
        "8. docker-compose: `privileged: true`, `hostNetwork: true`, "
        "secrets passed as plain env vars.\n\n"
        "Rules:\n"
        "- Set `location` to `path` or `path:job_name:step_name` where possible.\n"
        "- `module` should be 'cicd'.\n"
        "- Only report real issues with citable rationale.\n"
        "- Apply the SEVERITY DEFINITIONS above strictly — do not inflate."
    )

    structured = _get_llm().with_structured_output(_FileFindings)
    try:
        result: _FileFindings = structured.invoke(
            [{"role": "system", "content": system},
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
        p: c for p, c in files.items()
        if any(kw in p.lower() for kw in keywords)
    }
    if not auth_files:
        return _empty("No auth-related files identified by path.")

    bundle_parts: list[str] = []
    used = 0
    for p, c in auth_files.items():
        section = f"### {p}\n```\n{_truncate(c, 6000)}\n```"
        if used + len(section) > MAX_AUTH_BUNDLE_BYTES:
            break
        bundle_parts.append(section)
        used += len(section)
    bundle = "\n\n".join(bundle_parts)

    system = (
        "You are a senior AppSec engineer specialising in authentication. "
        "You are reviewing the full auth surface of an application.\n\n"
        f"{SEVERITY_RUBRIC}\n"
        f"{CVSS_AND_EXPOSURE_RUBRIC}\n"
        f"{COMPLIANCE_INSTRUCTIONS}\n"
        "Look for:\n"
        "- JWT validation gaps (alg confusion, missing aud/iss/exp, "
        "excessively long expiries, no signature verification).\n"
        "- OAuth: missing state parameter, PKCE absence on public clients, "
        "open redirect in redirect_uri.\n"
        "- Session: fixation, not invalidated on logout or password change, "
        "predictable IDs, missing Secure/HttpOnly/SameSite cookie flags.\n"
        "- Password reset: token reuse, weak entropy, no expiry, email "
        "enumeration.\n"
        "- Credential compare with == instead of constant-time compare.\n"
        "- Missing rate limits on login / reset / MFA endpoints.\n"
        "- IDOR in authenticated routes (handler fetches by ID without "
        "checking ownership).\n"
        "- Privilege escalation via mass-assignment of role/is_admin fields.\n\n"
        "Rules:\n"
        "- Cite specific file:line in `location`.\n"
        "- `module` should be 'auth' or 'authz' as appropriate.\n"
        "- Only report real, exploitable issues.\n"
        "- Apply the SEVERITY DEFINITIONS above strictly — do not inflate."
    )

    structured = _get_llm().with_structured_output(_FileFindings)
    try:
        result: _FileFindings = structured.invoke(
            [{"role": "system", "content": system},
             {"role": "user", "content": bundle}]
        )
        return result.model_dump_json()
    except Exception as exc:  # noqa: BLE001
        return _empty(f"ai_audit_auth_flow failed: {exc!s}")


AI_TOOLS = [ai_scan_file, ai_scan_cicd, ai_audit_auth_flow]

AI_TOOL_TO_MODULE = {
    "ai_scan_file":       ("ai_deep", "AI deep-file scan"),
    "ai_scan_cicd":       ("ai_cicd", "AI CI/CD audit"),
    "ai_audit_auth_flow": ("ai_auth", "AI auth-flow audit"),
}
