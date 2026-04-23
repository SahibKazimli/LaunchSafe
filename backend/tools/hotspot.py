"""Hotspot selector tool.

Ranks files from the ingested repo by risk relevance for a given
specialist lane.  Instead of agents guessing which files to scan,
they call ``select_hotspots("auth")`` and get back a pre-sorted list
of the most relevant files for their lane.

Uses two signals:
  1. ``RepoProfile.hotspot_files`` — recon's LLM-curated priority list.
  2. Path-pattern heuristics — keyword matching on file paths.

Files that appear in both lists rank highest.
"""

from __future__ import annotations

import json
from typing import Annotated

from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState

from core.config import SELECT_HOTSPOT_MAX_FILES


# Lane → path keywords.  A file matches a lane if any keyword appears
# anywhere in its lowercased path.  Order matters: earlier keywords are
# weighted slightly higher during sorting.
LANE_PATTERNS: dict[str, list[str]] = {
    "auth": [
        "auth", "login", "logout", "session", "jwt", "oauth", "password",
        "token", "middleware", "identity", "account", "signup", "register",
        "verify", "credential", "permission", "role", "acl", "rbac",
    ],
    "payments": [
        "stripe", "payment", "billing", "checkout", "order", "subscription",
        "invoice", "webhook", "charge", "refund", "price", "cart",
        "paypal", "adyen", "braintree",
    ],
    "iac": [
        ".tf", ".tfvars", "terraform", "cloudformation", "k8s", "kubernetes",
        "helm", "pulumi", "bicep", "cdk", "ansible", "kustomize",
        "deployment", "service.yaml", "ingress",
    ],
    "cicd": [
        ".github/workflows", "dockerfile", "docker-compose", ".gitlab-ci",
        "jenkinsfile", "circleci", "buildkite", "makefile", "justfile",
        ".github/actions", "pipeline",
    ],
    "general": [
        "route", "api", "controller", "handler", "endpoint", "view",
        "server", "app", "main", "index", "config", "setting", "env",
        "secret", "key", "database", "db", "model", "schema",
    ],
}

# Files to always de-prioritize regardless of lane.
_LOW_VALUE = frozenset({
    "readme", "license", "licence", "changelog", "contributing",
    "code_of_conduct", "authors", "notice",
})


def _is_low_value(path: str) -> bool:
    basename = path.rsplit("/", 1)[-1].rsplit(".", 1)[0].lower()
    return basename in _LOW_VALUE


def _score_file(
    path: str,
    lane: str,
    hotspot_set: set[str],
    hotspot_rank: dict[str, int],
    file_size: int,
) -> float:
    """Higher score = more relevant to scan for this lane."""
    score = 0.0
    lower = path.lower()

    # Signal 1: appears in recon's hotspot list
    if path in hotspot_set:
        # Boost by position in the hotspot list (earlier = higher)
        rank = hotspot_rank.get(path, 100)
        score += max(50 - rank * 2, 10)

    # Signal 2: path matches lane keywords
    patterns = LANE_PATTERNS.get(lane, LANE_PATTERNS["general"])
    for i, pattern in enumerate(patterns):
        if pattern in lower:
            # Earlier patterns in the list are stronger signals
            score += max(20 - i, 5)

    # Penalty for low-value files
    if _is_low_value(path):
        score -= 30

    # Slight boost for larger files (more code to audit) but cap it
    if file_size > 500:
        score += min(file_size / 5000, 5)

    return score


@tool
def select_hotspots(
    lane: str,
    state: Annotated[dict, InjectedState],
    max_files: int = SELECT_HOTSPOT_MAX_FILES,
) -> str:
    """Get the highest-priority files to scan for your specialist lane.

    Call this as your FIRST step instead of manually reading the file
    list. Returns files pre-sorted by relevance to your lane.

    Args:
        lane: Your specialist lane. One of: auth, payments, iac, cicd, general.
        max_files: Max files to return (default from ``SELECT_HOTSPOT_MAX_FILES`` / env).

    Returns JSON: {files: [{path, size_bytes, relevance}], lane, total_in_repo}.
    """
    files = state.get("files", {})
    profile = state.get("repo_profile") or {}

    hotspot_files = profile.get("hotspot_files") or []
    hotspot_set = set(hotspot_files)
    hotspot_rank = {path: priority for priority, path in enumerate(hotspot_files)}

    # Normalize lane
    lane_key = lane.strip().lower().replace("_audit", "").replace("_", "")
    if lane_key not in LANE_PATTERNS:
        lane_key = "general"

    # Score and rank every file
    scored: list[tuple[float, str, int]] = []
    for path, content in files.items():
        size = len(content)
        score = _score_file(path, lane_key, hotspot_set, hotspot_rank, size)
        if score > 0:
            scored.append((score, path, size))

    # Sort descending by score
    scored.sort(key=lambda x: -x[0])

    result_files = []
    for score, path, size in scored[:max_files]:
        # Build a human-readable relevance reason
        reasons = []
        if path in hotspot_set:
            reasons.append("recon hotspot")
        lower = path.lower()
        patterns = LANE_PATTERNS.get(lane_key, LANE_PATTERNS["general"])
        matched_patterns = [pattern for pattern in patterns if pattern in lower]
        if matched_patterns:
            reasons.append(f"matches: {', '.join(matched_patterns[:3])}")
        result_files.append({
            "path": path,
            "size_bytes": size,
            "relevance": " + ".join(reasons) or "general interest",
        })

    return json.dumps({
        "files": result_files,
        "lane": lane_key,
        "total_in_repo": len(files),
    })
