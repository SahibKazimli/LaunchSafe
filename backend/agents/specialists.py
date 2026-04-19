"""Specialist sub-agents that fan out in parallel after recon.

Each specialist is a `create_react_agent` wrapped in a node function.
The wrapper translates the agent's structured response into the merged
`branch_findings` state field (list-concat reducer in `state.py`), so
all branches can run concurrently without overwriting each other.

Branches:

  general_audit   — always runs; safety net for OWASP, secrets, deps,
                    anything outside the specialist lanes
  payments_audit  — runs if has_payments
  iac_audit       — runs if has_iac
  auth_audit      — runs if has_auth (covers crypto + session + IDOR)
  cicd_audit      — runs if has_cicd

Each specialist gets the FULL tool set so it can still explore. Its
prompt is what narrows the focus — that lets a specialist follow a thread
into adjacent code without us having to plumb a custom tool list.
"""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, Field

from .runtime_log import emit
from .schemas import COMPLIANCE_INSTRUCTIONS, SEVERITY_RUBRIC, Finding
from .state import ScanAgentState
from .tools.agent_tools import ALL_TOOLS as REGEX_TOOLS
from .tools.ai_tools import AI_TOOLS

ALL_AGENT_TOOLS = REGEX_TOOLS + AI_TOOLS

SPEC_RECURSION_LIMIT = 30
SPEC_MAX_TOKENS = 4096


class _BranchFindings(BaseModel):
    """What each specialist returns to the synthesizer."""
    findings: list[Finding] = Field(default_factory=list)
    notes: str = Field(
        default="",
        description="ONE sentence on what was checked / what stood out.",
    )



# Specialist prompts


_COMMON_TAIL = f"""\

{SEVERITY_RUBRIC}

{COMPLIANCE_INSTRUCTIONS}

Workflow:
  1. Re-read the RepoProfile in the first user message; pay attention
     to `hotspot_files`.
  2. Run the regex triage tools relevant to your lane (cheap, free).
  3. For each in-scope hotspot, call `ai_scan_file` with the focus that
     fits your lane. Use `read_file` only for adaptive follow-ups.
  4. Return a `_BranchFindings` object. Keep findings to your lane —
     overlap is OK if you have stronger evidence than another specialist
     would, but do NOT pad the list.

Hard rules:
  - Cap findings at 10 per call. If you have more, keep the most
    severe / most exploitable ones.
  - Drop obvious test fixtures, EXAMPLE keys, and docs.
  - One sentence in `notes` summarising what you checked. If you found
    nothing, say so explicitly — empty findings + "checked X, Y, Z, all
    clean" is a valid, useful result.
"""


PAYMENTS_PROMPT = f"""\
You are a senior application-security engineer specialising in PAYMENT
SYSTEMS. Your lane: anywhere money or cardholder data moves.

You ONLY produce findings for:
  - Stripe / Adyen / Braintree / PayPal SDK misuse (publishable vs
    secret key confusion, secret key in client code, missing webhook
    signature verification).
  - Webhook handler security: signature checks, replay protection,
    idempotency.
  - Storing or logging PAN, CVV, full card numbers — even partially.
  - PCI-DSS scope leakage: payment data flowing into systems that
    shouldn't see it (general logs, analytics, third-party SDKs).
  - Payment IDOR: can a user trigger refunds, view orders, modify
    amounts on items not their own?
  - Currency / amount manipulation (client-trusted price, integer
    overflow on amount, missing min/max bounds).
  - Subscription / billing logic that lets a user escalate plan or
    bypass payment.

Out of your lane (let other specialists handle):
  - Generic auth / session / JWT (auth_audit's job)
  - Cloud config / Terraform (iac_audit's job)
  - Generic SQL injection unrelated to payments (general_audit's job)
{_COMMON_TAIL}"""


IAC_PROMPT = f"""\
You are a senior cloud-security engineer specialising in INFRASTRUCTURE
AS CODE. Your lane: anything that provisions cloud or container resources.

You ONLY produce findings for:
  - Terraform / OpenTofu: publicly_accessible RDS/databases, S3 buckets
    with public ACLs or BucketPolicy, unrestricted security groups
    (0.0.0.0/0 on SSH/RDP/DB ports), IAM policies with `Action: "*"` or
    `Resource: "*"`, missing encryption at rest, secrets in *.tf or
    *.tfvars committed to the repo.
  - CloudFormation: same patterns; PublicAccessBlockConfiguration absent;
    VPC defaults; oversized IAM roles attached to compute.
  - Kubernetes manifests: containers running as root, missing
    securityContext, hostNetwork/hostPID true, privileged: true,
    capabilities ADD ALL, ServiceAccount with cluster-admin.
  - Helm charts and kustomize overlays with the same issues.
  - Pulumi / CDK code that exposes the above patterns.

Out of your lane:
  - Application code (route handlers, business logic, DB queries)
  - CI/CD workflows (cicd_audit's job)
  - Dockerfile content (cicd_audit's job)
{_COMMON_TAIL}"""


AUTH_PROMPT = f"""\
You are a senior application-security engineer specialising in
AUTHENTICATION, AUTHORIZATION, AND CRYPTOGRAPHY. This is one combined
lane because they share threat models.

You ONLY produce findings for:
  - JWT: alg=none accepted, no signature verification, missing exp /
    aud / iss, excessively long expiries, weak/leaked HS256 secret,
    confused deputy with multiple keys.
  - OAuth: missing state, no PKCE on public client, redirect_uri open
    redirect, implicit flow used in 2024+.
  - Sessions: predictable IDs, no rotation on privilege change, missing
    Secure / HttpOnly / SameSite cookie flags, session not invalidated
    on logout / password change.
  - Password storage: MD5 / SHA1 / SHA256 unsalted / bcrypt with low
    cost factor; missing pepper; reversible "encryption" instead of
    hashing.
  - Credential / token compare with `==` instead of constant-time
    (`hmac.compare_digest`).
  - Missing rate limit on /login, /reset, /mfa, /signup.
  - IDOR / broken object-level authz: handler fetches by ID without
    checking the requesting user owns or can access the resource.
  - Mass-assignment: user-supplied JSON setting `is_admin`, `role`,
    `tenant_id`, etc.
  - Crypto misuse: weak algorithms (MD5, SHA1, DES), ECB mode, reused
    or static IVs, weak PRNG (`random` instead of `secrets`) for
    security tokens, hardcoded keys.

Out of your lane:
  - Payment-flow auth (payments_audit covers that)
  - CI/CD secret handling (cicd_audit covers that)
  - Cloud IAM (iac_audit covers that)
{_COMMON_TAIL}"""


CICD_PROMPT = f"""\
You are a DevSecOps engineer specialising in CI/CD AND SUPPLY-CHAIN
security. Your lane: anything that builds, tests, or deploys the code.

You ONLY produce findings for:
  - GitHub Actions: pull_request_target + checkout of PR ref (RCE),
    actions pinned by tag/branch (`@v2`, `@main`) instead of SHA,
    `${{{{ github.event.* }}}}` or `github.head_ref` interpolated into
    `run:` (script injection), `permissions: write-all` or no
    `permissions:` on sensitive jobs, secrets echoed to logs,
    self-hosted runners on public-trigger workflows.
  - GitLab CI / CircleCI / Buildkite: equivalent patterns.
  - Dockerfile: USER root (no USER directive), `ADD <url>` for remote
    fetches, `:latest` base images, `apt-get install` without `&& rm
    -rf /var/lib/apt/lists/*`, secrets baked into image layers.
  - docker-compose: `privileged: true`, `network_mode: host`, secrets
    passed as plain env vars, exposed daemon socket.
  - Build scripts (Makefile, package.json scripts, justfile) that pipe
    `curl | bash` or download unverified binaries.
  - Dependency manifests with known typosquats / abandoned packages.

Out of your lane:
  - Application code (let other specialists handle)
  - Cloud IAM (iac_audit covers that)

When you call `ai_scan_cicd`, that tool already audits the full bundle —
prefer one call to it over many individual `ai_scan_file` calls on
workflow files.
{_COMMON_TAIL}"""


GENERAL_PROMPT = f"""\
You are a senior application-security engineer doing the general OWASP
sweep. You are the SAFETY NET — anything the lane specialists miss is
your responsibility.

You ALWAYS run, regardless of repo profile. Your lane:
  - Hardcoded secrets in source (live keys, real DB URLs, private keys).
    Always run the `scan_secrets_tool` regex first as a free pre-pass.
  - Generic SQL / NoSQL injection that is NOT payment-specific.
  - Server-side request forgery (SSRF), open redirects, path traversal,
    XXE, insecure deserialization.
  - Reflected and stored XSS in templates / API responses.
  - Outdated or known-vulnerable dependencies (call
    `scan_dependencies_tool`).
  - Privacy / PII exposure: logging, analytics, error pages.
  - Missing security headers, CORS wildcards on authenticated APIs,
    DEBUG=True committed.
  - Anything genuinely exploitable that doesn't fit a specialist lane.

Out of your lane (don't double-up):
  - Payments / Stripe (payments_audit owns)
  - JWT / OAuth / sessions / password storage / crypto (auth_audit owns)
  - Terraform / k8s / CloudFormation (iac_audit owns)
  - GitHub Actions / Dockerfile / docker-compose (cicd_audit owns)

If a specialist covers it, drop it from your output — duplicates get
deduped by the synthesizer but waste your token budget.
{_COMMON_TAIL}"""



_AGENTS: dict[str, Any] = {}


def _build_specialist(name: str, prompt: str):
    from langchain_anthropic import ChatAnthropic
    from langgraph.prebuilt import create_react_agent

    model_name = os.environ.get("LAUNCHSAFE_LLM_MODEL", "claude-sonnet-4-5")
    llm = ChatAnthropic(model=model_name, max_tokens=SPEC_MAX_TOKENS, temperature=0)

    return create_react_agent(
        model=llm,
        tools=ALL_AGENT_TOOLS,
        state_schema=ScanAgentState,
        prompt=prompt,
        response_format=_BranchFindings,
    )


def _get_agent(name: str, prompt: str):
    if name not in _AGENTS:
        _AGENTS[name] = _build_specialist(name, prompt)
    return _AGENTS[name]


def _summarize_inner_messages(name: str, scan_id: str, messages: list) -> int:
    """After a branch finishes, walk its inner messages and emit one event
    per AI thought / tool call / tool result — all tagged with the branch.
    Returns the number of tool calls observed (useful for progress UI)."""
    tool_calls = 0
    for msg in messages or []:
        msg_type = getattr(msg, "type", None)
        if msg_type == "ai":
            for tc in getattr(msg, "tool_calls", None) or []:
                tool_calls += 1
                tc_name = tc.get("name", "?") if isinstance(tc, dict) else "?"
                args = tc.get("args") or {} if isinstance(tc, dict) else {}
                arg_parts = []
                for k, v in list(args.items())[:2]:
                    s = str(v)
                    if len(s) > 50:
                        s = s[:47] + "…"
                    arg_parts.append(f"{k}={s}")
                emit(scan_id, "call", f"{tc_name}({', '.join(arg_parts)})", branch=name)
            content = getattr(msg, "content", "")
            if isinstance(content, str) and content.strip():
                emit(scan_id, "think", content.strip(), branch=name)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        txt = (block.get("text") or "").strip()
                        if txt:
                            emit(scan_id, "think", txt, branch=name)
        elif msg_type == "tool":
            tool_name = getattr(msg, "name", "?")
            content = getattr(msg, "content", "") or ""
            size = len(content) if isinstance(content, str) else 0
            emit(scan_id, "result", f"{tool_name} → {size}B", branch=name)
    return tool_calls


def _make_specialist_node(name: str, prompt: str, kickoff_msg: str):
    """Return an async graph node that runs the named specialist and writes
    its findings into `branch_findings` (tagged with the branch name)."""

    async def node(state: dict[str, Any]) -> dict[str, Any]:
        scan_id = state.get("scan_id", "")
        emit(scan_id, "branch_start", f"{name} specialist starting", branch=name)

        agent = _get_agent(name, prompt)
        try:
            result = await agent.ainvoke(
                {
                    "messages": [{"role": "user", "content": kickoff_msg}],
                    "files": state.get("files", {}),
                    "repo_profile": state.get("repo_profile", {}),
                    "scan_id": scan_id,
                    "target": state.get("target", ""),
                    "branch_findings": [],
                },
                {"recursion_limit": SPEC_RECURSION_LIMIT},
            )
        except Exception as exc:  # noqa: BLE001
            emit(scan_id, "warn", f"{name} crashed: {str(exc)[:140]}", branch=name)
            return {
                "branch_findings": [
                    {"_branch": name, "_error": str(exc)[:200]}
                ]
            }

        tool_calls = _summarize_inner_messages(name, scan_id, result.get("messages", []))

        sr = result.get("structured_response")
        if sr is None:
            emit(
                scan_id,
                "branch_done",
                f"{name} returned no structured response after {tool_calls} tool calls",
                branch=name,
                count=0,
                tool_calls=tool_calls,
            )
            return {"branch_findings": []}

        tagged: list[dict] = []
        for f in getattr(sr, "findings", []) or []:
            d = f.model_dump()
            d["_branch"] = name
            tagged.append(d)

        emit(
            scan_id,
            "branch_done",
            f"{name} finished: {len(tagged)} finding(s) from {tool_calls} tool calls",
            branch=name,
            count=len(tagged),
            tool_calls=tool_calls,
        )
        return {"branch_findings": tagged}

    node.__name__ = f"{name}_node"
    return node



# Public API: one node per specialist + the conditional router


_KICKOFF = (
    "Recon is complete; the RepoProfile is in your state. Audit this "
    "repo within YOUR lane only. Use the regex triage tools first, "
    "then ai_scan_file on the relevant hotspots. Return a _BranchFindings."
)

payments_audit_node = _make_specialist_node("payments", PAYMENTS_PROMPT, _KICKOFF)
iac_audit_node      = _make_specialist_node("iac",      IAC_PROMPT,      _KICKOFF)
auth_audit_node     = _make_specialist_node("auth",     AUTH_PROMPT,     _KICKOFF)
cicd_audit_node     = _make_specialist_node("cicd",     CICD_PROMPT,     _KICKOFF)
general_audit_node  = _make_specialist_node("general",  GENERAL_PROMPT,  _KICKOFF)


SPECIALIST_NODES: dict[str, Any] = {
    "payments_audit": payments_audit_node,
    "iac_audit":      iac_audit_node,
    "auth_audit":     auth_audit_node,
    "cicd_audit":     cicd_audit_node,
    "general_audit":  general_audit_node,
}


def route_after_recon(state: dict[str, Any]) -> list[str]:
    """Decide which specialist branches run, based on the RepoProfile.

    `general_audit` always runs as a safety net. Others gate on the
    capability flags recon emitted.
    """
    profile = state.get("repo_profile") or {}
    branches = ["general_audit"]
    if profile.get("has_payments"): branches.append("payments_audit")
    if profile.get("has_iac"):      branches.append("iac_audit")
    if profile.get("has_auth"):     branches.append("auth_audit")
    if profile.get("has_cicd"):     branches.append("cicd_audit")
    return branches
