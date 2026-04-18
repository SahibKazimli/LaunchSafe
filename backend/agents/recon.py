"""Repo-intake recon: the LLM's first pass over an ingested codebase.

Runs before the ReAct audit loop. Feeds Claude a compact manifest (all file
paths + full contents of a handful of key config/manifest files) and gets
back a structured `RepoProfile` describing the stack, surface area, and
where to look hardest. The profile is injected into the agent's messages
so the downstream ReAct loop starts already knowing what the app is.
"""

from __future__ import annotations

import json
import os
from typing import Any

from pydantic import BaseModel, Field

KEY_FILENAMES = {
    "README.md", "README", "readme.md",
    "package.json", "requirements.txt", "pyproject.toml", "Pipfile",
    "Gemfile", "go.mod", "Cargo.toml", "pom.xml", "build.gradle",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".env.example", ".env.sample",
    "next.config.js", "vite.config.ts", "vite.config.js",
    "tsconfig.json",
}

KEY_DIR_HINTS = ("terraform/", "infra/", ".github/workflows/", "k8s/", "helm/")

MAX_MANIFEST_PATHS = 400
MAX_SNIPPET_BYTES = 4000


RECON_PROMPT = """\
You are a senior security auditor doing an initial reconnaissance pass on
a codebase before running any scanners. You will receive:
  - the full list of file paths in the repo
  - the full contents of a handful of key manifest/config files

Your job is to return a structured RepoProfile describing what this
application is, where the sensitive surface area lives, and which files
the scanner step should focus on. Be concrete and cite real paths.

Do NOT call any tools. Do NOT try to find specific vulnerabilities yet —
that is the next step. Focus on understanding the system.
"""


class RepoProfile(BaseModel):
    stack: str = Field(description="one-sentence stack summary, e.g. 'FastAPI backend + React frontend + Postgres, deployed to AWS via Terraform'")
    languages: list[str] = Field(default_factory=list, description="primary languages present")
    frameworks: list[str] = Field(default_factory=list, description="detected frameworks / libraries of note")
    has_iac: bool = Field(description="true if Terraform / CloudFormation / k8s manifests / Pulumi present")
    has_auth: bool = Field(description="true if auth / session / JWT / OAuth code is present")
    has_payments: bool = Field(description="true if payment processing (Stripe, etc.) is integrated")
    has_user_data: bool = Field(description="true if the app appears to store user PII")
    entry_points: list[str] = Field(
        default_factory=list,
        description="file paths that are likely HTTP entry points or main() equivalents",
    )
    risk_hotspots: list[str] = Field(
        default_factory=list,
        description="file paths most worth deep-diving during the scanner step (auth, routes, IaC, config, secrets-adjacent files)",
    )
    summary: str = Field(description="2-3 sentence plain-English description of the app and its headline risk surface")


def _build_manifest(files: dict[str, str]) -> str:
    paths = sorted(files.keys())

    snippets: dict[str, str] = {}
    for p in paths:
        base = p.rsplit("/", 1)[-1]
        is_key_file = base in KEY_FILENAMES
        is_key_dir = any(p.startswith(prefix) or ("/" + prefix) in p for prefix in KEY_DIR_HINTS)
        if is_key_file or (is_key_dir and p.endswith((".tf", ".yaml", ".yml"))):
            content = files[p]
            if len(content) > MAX_SNIPPET_BYTES:
                content = content[:MAX_SNIPPET_BYTES] + "\n...[truncated]"
            snippets[p] = content

    manifest = {
        "file_count": len(files),
        "file_paths": paths[:MAX_MANIFEST_PATHS],
        "paths_truncated": len(paths) > MAX_MANIFEST_PATHS,
        "key_file_contents": snippets,
    }
    return json.dumps(manifest, default=str)


def recon_node(state: dict[str, Any]) -> dict[str, Any]:
    """Build a RepoProfile from the ingested files and seed the agent context."""
    from langchain_anthropic import ChatAnthropic
    from langchain_core.messages import HumanMessage

    files = state.get("files", {})
    if not files:
        empty = RepoProfile(
            stack="unknown (no files ingested)",
            has_iac=False, has_auth=False, has_payments=False, has_user_data=False,
            summary="No files were ingested.",
        )
        return {"repo_profile": empty.model_dump(), "messages": []}

    model_name = os.environ.get("LAUNCHSAFE_LLM_MODEL", "claude-sonnet-4-5")
    llm = ChatAnthropic(model=model_name, max_tokens=2048, temperature=0)
    structured = llm.with_structured_output(RepoProfile)

    manifest = _build_manifest(files)
    profile: RepoProfile = structured.invoke([
        {"role": "system", "content": RECON_PROMPT},
        HumanMessage(content=manifest),
    ])

    context_msg = HumanMessage(content=(
        "Recon is complete. Here is the RepoProfile:\n\n"
        f"{profile.model_dump_json(indent=2)}\n\n"
        "Use this to prioritise which scanners to run and which files to "
        "read_file on. Now produce the final AuditReport."
    ))

    return {
        "repo_profile": profile.model_dump(),
        "messages": [context_msg],
    }
