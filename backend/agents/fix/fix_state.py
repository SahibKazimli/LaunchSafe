"""State schemas for the fix session graph.

Kept separate from scan state (agents/state.py) so the two pipelines
are fully decoupled.  Changes here never affect scan reliability.
"""

from __future__ import annotations

from operator import add
from typing import Annotated, Any, TypedDict

from pydantic import BaseModel, Field


# ── Pydantic models (structured LLM output) ──────────────────────────


class FilePatch(BaseModel):
    """One file's before/after with a human-readable diff."""

    path: str = Field(description="Relative file path in the repo")
    original_snippet: str = Field(
        default="",
        description=(
            "The relevant section of the original file that was changed. "
            "Include enough surrounding context (5-10 lines) so a reviewer "
            "can see where the change sits."
        ),
    )
    patched_snippet: str = Field(
        default="",
        description=(
            "The same section after the fix is applied.  Must be a drop-in "
            "replacement for original_snippet."
        ),
    )
    diff: str = Field(
        default="",
        description=(
            "Unified diff (--- a/path, +++ b/path, @@ lines) showing "
            "exactly what changed.  Generate this yourself from the "
            "original and patched snippets."
        ),
    )
    explanation: str = Field(
        default="",
        description="One sentence: what was changed and why it fixes the issue.",
    )


class FixGroup(BaseModel):
    """A logical batch of related findings to fix together."""

    group_id: str = Field(
        description=(
            "Short slug for this group, e.g. 'auth-hardening', "
            "'sql-parameterize', 'secrets-rotate'."
        )
    )
    label: str = Field(
        default="",
        description="Human-readable label, e.g. 'Authentication Hardening'",
    )
    finding_indices: list[int] = Field(
        default_factory=list,
        description="Indices into the findings list that belong to this group",
    )
    target_files: list[str] = Field(
        default_factory=list,
        description="File paths that need to be modified for this group",
    )
    risk_level: str = Field(
        default="medium",
        description=(
            "Blast radius of the fix: 'low' (formatting, headers), "
            "'medium' (logic changes), 'high' (auth/payment/crypto)."
        ),
    )
    commit_message: str = Field(
        default="",
        description=(
            "Conventional commit message for this group, e.g. "
            "'fix(auth): enforce HS256 algorithm in JWT verification'"
        ),
    )
    rationale: str = Field(
        default="",
        description="One sentence: why these findings are grouped together.",
    )


class FixPlan(BaseModel):
    """Output of the planning node — how to batch the fixes."""

    groups: list[FixGroup] = Field(default_factory=list)
    execution_order: list[str] = Field(
        default_factory=list,
        description=(
            "group_ids in the order they should be applied.  "
            "Config/dependency fixes first, then code that reads them."
        ),
    )
    notes: str = Field(
        default="",
        description="Any caveats or manual steps the user should know about.",
    )


class PatchResult(BaseModel):
    """Output of one fix worker — patches for one group."""

    group_id: str
    patches: list[FilePatch] = Field(default_factory=list)
    notes: str = Field(
        default="",
        description="What was changed and any caveats.",
    )


class PatchReview(BaseModel):
    """Output of the review node."""

    approved: bool = Field(
        default=True,
        description="True if patches are conflict-free and safe to apply.",
    )
    conflicts: list[str] = Field(
        default_factory=list,
        description="Descriptions of any conflicts found between patches.",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Non-blocking concerns the user should be aware of.",
    )
    notes: str = Field(default="")


# Graph state


class FixSessionState(TypedDict):
    """State flowing through the fix graph.

    ``patch_results`` uses a list-concat reducer so parallel workers
    (if we fan out later) can each append without overwriting.
    """

    # Inputs (set by load_context)
    scan_id: str
    fix_id: str
    target: str
    findings: list[dict]
    files: dict[str, str]
    repo_profile: dict

    # Planning output
    fix_plan: dict  # FixPlan.model_dump()

    # Patch generation (concat reducer for potential parallelism)
    patch_results: Annotated[list[dict], add]

    # Review output
    review_result: dict  # PatchReview.model_dump()
