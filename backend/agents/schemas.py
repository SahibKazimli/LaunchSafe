"""Shared Pydantic schemas used across the agent layer.

Living in its own module so `graph.py`, `recon.py`, and the AI tools in
`tools/ai_tools.py` can all import them without cycles.

Severity / compliance **prompt rubrics** live in :mod:`agents.prompts.audit_rubrics`
and are re-exported here for backward compatibility.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import AliasChoices, BaseModel, Field, model_validator

from agents.prompts.audit_rubrics import (
    COMPLIANCE_INSTRUCTIONS,
    CVSS_AND_EXPOSURE_RUBRIC,
    SEVERITY_RUBRIC,
)

Exposure = Literal["production", "internal", "test", "example", "doc"]


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
            "ONE plain-English sentence (≤ 30 words) for a startup founder, "
            "not a security expert. State (a) what the control requires, in "
            "concrete terms, AND (b) why the founder should care (fines, "
            "audit blocker, customer trust). No jargon."
        )
    )
    url: Optional[str] = Field(
        default=None,
        description=(
            "DEEP link to the specific control / article — NOT a homepage. "
            "Examples: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/', "
            "'https://gdpr-info.eu/art-32-gdpr/', "
            "'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'. "
            "Set to null if you don't know the exact deep URL — never guess "
            "and never link to a framework root page."
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

    cvss_base: float = Field(
        default=0.0,
        ge=0.0,
        le=10.0,
        description=(
            "CVSS v3.1 base score (0.0-10.0) for THIS finding. Pick a "
            "concrete number inside the qualitative band that matches "
            "your `severity`: Critical 9.0-10.0, High 7.0-8.9, "
            "Medium 4.0-6.9, Low 0.1-3.9. Push toward the LOW end of "
            "the band by default — only go to the top of the band when "
            "exploitation is trivial AND impact is catastrophic. You do "
            "not need to compute the full vector; just pick the number."
        ),
    )
    exposure: Exposure = Field(
        default="production",
        description=(
            "Where this code actually runs in the deployed system, "
            "based on the file path and the RepoProfile. Pick exactly "
            "one:\n"
            "  production — code that ships to real users; live request "
            "    handlers, prod IaC, prod CI/CD, prod auth, prod DB.\n"
            "  internal   — admin tools, internal scripts, prod-only "
            "    debug endpoints, ops tooling.\n"
            "  test       — anything under tests/, __tests__, spec/, "
            "    *_test.*, conftest.py, test fixtures.\n"
            "  example    — sample/demo code in examples/, samples/, "
            "    cookbook/, notebooks intended as tutorials.\n"
            "  doc        — documentation snippets in docs/, README "
            "    samples, sphinx examples.\n"
            "Library / framework repos (FastAPI, Django, etc.) almost "
            "never have `production` code — most matches will be "
            "test/example/doc."
        ),
    )


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
    # Booleans default False so structured output from models that omit keys
    # (e.g. Gemini) still parses; recon prompt still asks for explicit values.
    has_iac: bool = Field(
        default=False,
        description="Terraform / CloudFormation / k8s / Pulumi present",
    )
    has_cicd: bool = Field(
        default=False,
        description=".github/workflows or similar CI/CD present",
    )
    has_auth: bool = Field(
        default=False,
        description="auth / session / JWT / OAuth code present",
    )
    has_payments: bool = Field(
        default=False,
        description="payment processor (Stripe, etc.) integrated",
    )
    has_user_data: bool = Field(
        default=False,
        description="app appears to store user PII",
    )
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
    summary: str = Field(
        default="",
        description="2-3 sentence description of the app and its headline risk surface",
        validation_alias=AliasChoices("summary", "overview", "description"),
    )

    @model_validator(mode="after")
    def _ensure_summary(self) -> RepoProfile:
        """LLMs often emit ``overview``; aliases cover that. Fall back to ``stack``."""
        if not (self.summary or "").strip() and (self.stack or "").strip():
            return self.model_copy(update={"summary": self.stack})
        return self
