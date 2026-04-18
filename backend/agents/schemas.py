"""Shared Pydantic schemas used across the agent layer.

Living in its own module so `graph.py`, `recon.py`, and the AI tools in
`tools/ai_tools.py` can all import them without cycles.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


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
    compliance: list[str] = Field(default_factory=list)


class AuditReport(BaseModel):
    summary: str = Field(description="2-4 sentence executive summary")
    findings: list[Finding]
    top_fixes: list[str] = Field(
        description="3-5 imperative sentences: what to do Monday morning",
    )
    overall_risk: str = Field(description="one of: critical, high, medium, low, minimal")


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
