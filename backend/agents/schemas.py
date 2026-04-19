"""Shared Pydantic schemas used across the agent layer.

Living in its own module so `graph.py`, `recon.py`, and the AI tools in
`tools/ai_tools.py` can all import them without cycles.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

SEVERITY_RUBRIC = """\
SEVERITY DEFINITIONS — be strict and consistent. Pick the LOWEST band that
honestly fits; do not inflate.

  critical: Direct, immediate, unauthenticated impact. Blast radius = whole app
    or all users. Exploitable today, no chained conditions. Examples:
    - Live production secret committed (real AKIA*, sk_live_, ghp_, real DB URL).
    - Pre-auth RCE (eval/exec/popen/shell on attacker-controlled input).
    - SQL injection on a public endpoint exposing user data.
    - Authentication completely bypassable (alg=none accepted, no signature check).
    - publicly_accessible=true on a database holding user data.
    - 0.0.0.0/0 SSH/RDP on production infra.

  high: Exploitable with mild friction (needs a user account, a specific input
    shape, or chaining 2 small steps). Blast radius = many users or sensitive
    data. Examples:
    - SQL injection behind login.
    - Broken object-level authorization (IDOR) on user data.
    - MD5 / SHA1 used for password hashing or session tokens.
    - JWT with no expiry, or week+ expiry, or weak/default secret.
    - Server-side request forgery to internal network.
    - cors origin '*' on an authenticated API that returns user data.
    - Stored XSS in user-rendered content.
    - Public S3 bucket with non-trivial PII.

  medium: Realistic exploit chain but limited blast radius, OR a security
    control gap that materially weakens defense-in-depth. Examples:
    - Missing rate limit on /login or /reset (enables credential stuffing).
    - Missing CSRF protection on state-changing endpoints.
    - Verbose error messages leaking stack traces or internal paths.
    - Outdated dependency with a known CVE in a code path that IS reachable.
    - Missing security headers (CSP, HSTS, X-Frame-Options) on a real app.
    - Reflected XSS that requires social engineering.
    - Insecure deserialization on internal-only data.

  low: Best-practice violation, information disclosure, or hardening gap with
    no plausible direct exploit. Examples:
    - DEBUG=True committed to a config file.
    - Missing HttpOnly / SameSite on a non-session cookie.
    - Hardcoded EXAMPLE / TEST / FAKE credentials clearly labelled as such.
    - Tech-stack disclosure in HTTP headers (Server, X-Powered-By).
    - Outdated dependency with a CVE that is NOT reachable from app code.
    - TODO/FIXME comments referencing security work.

Calibration anchors (so the score makes sense across repos):
  - A typical hackathon / early-stage repo should have 0-2 critical, 2-6 high,
    4-10 medium, and the rest low.
  - If you find yourself emitting >3 critical findings, re-read each one and
    ask: is this REALLY pre-auth RCE / live secret / data-takeover? If not,
    drop it to high.
  - Hardcoded "EXAMPLE", "test", "dummy", "fake" credentials -> low at most
    (or skip if obviously a fixture).
  - Vulnerabilities only triggerable in dev mode (DEBUG=True path) -> max medium.
  - Set is_true_positive=False (don't drop the finding entirely) if you're
    less than ~70% sure it's exploitable in production.
"""

COMPLIANCE_INSTRUCTIONS = """\
COMPLIANCE REFERENCES — for every finding, attach the compliance controls
it actually violates. Each reference is an OBJECT with three fields:

  id:      Short identifier shown to the user. Use canonical, recognisable
           form. Examples:
             "OWASP A01:2021"           "OWASP A03:2021"           "OWASP API1:2023"
             "GDPR Art. 32"             "GDPR Art. 5"
             "CCPA §1798.150"
             "SOC 2 CC6.1"              "SOC 2 CC7.2"
             "ISO 27001 A.9.2"          "ISO 27001 A.12.4"
             "NIST SP 800-53 AC-2"      "NIST SP 800-53 SC-13"
             "PCI DSS 6.5.1"            "PCI DSS 8.2.3"
             "HIPAA §164.312(a)(1)"

  summary: ONE sentence, ≤ 25 words, plain language, engineer-facing.
           Describe what the control REQUIRES (not the violation).
           Examples:
             "Restrict access so users can only see and modify resources
              they are authorised for."
             "Enforce processor-level security: encryption, access control,
              and confidentiality of personal data."
             "Use cryptographically strong, salted hashing (Argon2/bcrypt)
              for stored passwords; never MD5/SHA1."

  url:     Canonical authoritative URL. Prefer these stable roots:
             OWASP Top 10:        https://owasp.org/Top10/
             OWASP API Top 10:    https://owasp.org/API-Security/editions/2023/en/
             OWASP cheatsheets:   https://cheatsheetseries.owasp.org/cheatsheets/
             GDPR articles:       https://gdpr-info.eu/art-XX-gdpr/
             NIST 800-53:         https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search
             AICPA SOC 2 / TSC:   https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2
             ISO 27001:           https://www.iso.org/standard/82875.html
             PCI DSS:             https://www.pcisecuritystandards.org/document_library/
             HIPAA Security Rule: https://www.hhs.gov/hipaa/for-professionals/security/
           If you do NOT know the exact URL, set url to null. Do NOT
           hallucinate URLs.

Rules:
  - Only attach a control if it is REALLY violated by this specific finding.
    Do not pad the list to look thorough.
  - Typical finding has 1–3 references. More than 4 is almost always padding.
  - For pure code-quality issues with no compliance angle, return an empty list.
"""


class ComplianceRef(BaseModel):
    """One compliance / standard control violated by a finding.

    The agent populates these directly so the UI can show a hover popover
    with a plain-language explanation and a link to the authoritative source.
    """
    id: str = Field(
        description=(
            "Short identifier shown to the user, e.g. 'OWASP A03:2021', "
            "'GDPR Art. 32', 'SOC 2 CC6.1', 'ISO 27001 A.9.2', "
            "'NIST SP 800-53 AC-2', 'CCPA §1798.150'."
        )
    )
    summary: str = Field(
        description=(
            "ONE sentence (≤ 25 words) in plain language explaining what the "
            "control requires. Engineer-facing, not marketing."
        )
    )
    url: Optional[str] = Field(
        default=None,
        description=(
            "Canonical URL for this control. Omit (null) rather than guess "
            "if you don't know the exact URL."
        ),
    )


class Finding(BaseModel):
    severity: str = Field(description="one of: critical, high, medium, low")
    module: str = Field(description="one of: secrets, auth, api, cloud, privacy, deps, cicd, authz, crypto, ssrf, injection, general")
    title: str
    location: str = Field(description="path[:line] — the file and, if known, the line number")
    description: str
    fix: str
    priority: int = Field(description="1 (most urgent) to 5", ge=1, le=5)
    is_true_positive: bool = True
    rationale: Optional[str] = None
    compliance: list[ComplianceRef] = Field(default_factory=list)


class AuditReport(BaseModel):
    summary: str = Field(default="", description="2-4 sentence executive summary")
    findings: list[Finding] = Field(default_factory=list)
    top_fixes: list[str] = Field(
        default_factory=list,
        description="3-5 imperative sentences: what to do Monday morning",
    )
    overall_risk: str = Field(
        default="medium",
        description="one of: critical, high, medium, low, minimal",
    )


class RepoProfile(BaseModel):
    stack: str = Field(description="one-sentence stack summary, e.g. 'FastAPI + React + Postgres on AWS via Terraform'")
    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    has_iac: bool = Field(description="Terraform / CloudFormation / k8s / Pulumi present")
    has_cicd: bool = Field(description=".github/workflows or similar CI/CD present")
    has_auth: bool = Field(description="auth / session / JWT / OAuth code present")
    has_payments: bool = Field(description="payment processor (Stripe, etc.) integrated")
    has_user_data: bool = Field(description="app appears to store user PII")
    entry_points: list[str] = Field(
        default_factory=list,
        description="file paths likely to be HTTP entry points or main() equivalents",
    )
    hotspot_files: list[str] = Field(
        default_factory=list,
        description=(
            "file paths that deserve AI deep-scanning. Ordered by scrutiny "
            "priority. Include: auth modules, route/controller files, DB "
            "layer, IaC, CI/CD workflows, files handling user input."
        ),
    )
    summary: str = Field(description="2-3 sentence description of the app and its headline risk surface")
