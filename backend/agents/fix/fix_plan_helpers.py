"""Fix planner support: resolve which repo files a batch touches, and server-side
coercion when the LLM returns invalid mega-groups (too many findings, or mixing
dependency manifests with application code).

Kept separate from :mod:`fix_nodes` so the graph file stays a thin list of
LangGraph node implementations.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from core.config import FIX_PLAN_MAX_FINDINGS_PER_GROUP
from core.finding_files import (
    infer_paths_from_finding_text,
    resolve_path_to_canonical_key,
    resolve_paths_for_findings,
)

# Basenames of lockfiles and manifests: never batched in the same FixGroup as code.
_MANIFEST_BASENAMES: frozenset[str] = frozenset(
    name.lower()
    for name in (
        "requirements.txt",
        "requirements.in",
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "go.mod",
        "go.sum",
        "pyproject.toml",
        "poetry.lock",
        "pipfile",
        "pipfile.lock",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "bun.lockb",
        "cargo.toml",
        "cargo.lock",
        "gemfile",
        "gemfile.lock",
        "composer.json",
        "composer.lock",
        "pom.xml",
    )
)


def slugify_title_for_group_id(title: str, fallback_index: int) -> str:
    """Stable kebab-case id from a finding title (for ``FixGroup.group_id``)."""
    raw = (title or "").strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "-", raw).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    slug = slug[:56] if slug else ""
    return slug if slug else f"finding-{fallback_index}"


def ensure_fix_group_metadata(groups: list[dict], findings: list[dict]) -> None:
    """Fill missing ``label`` / ``group_id`` and replace generic ``fix-N`` ids with title slugs."""
    used: set[str] = set()

    def _first_title(indices: list[Any]) -> str:
        for raw_idx in indices:
            if not isinstance(raw_idx, int):
                continue
            if 0 <= raw_idx < len(findings) and isinstance(findings[raw_idx], dict):
                t = str(findings[raw_idx].get("title") or "").strip()
                if t:
                    return t
        return ""

    for i, group in enumerate(groups or []):
        if not isinstance(group, dict):
            continue
        indices = [x for x in (group.get("finding_indices") or []) if isinstance(x, int)]
        first_title = _first_title(indices)
        label = (group.get("label") or "").strip()
        if not label and first_title:
            group["label"] = first_title[:220]
            label = group["label"]
        group_id = (group.get("group_id") or "").strip()
        generic = bool(re.fullmatch(r"fix-\d+", group_id))
        if (not group_id or generic) and (label or first_title):
            base = slugify_title_for_group_id(label or first_title, i)
            new_id = base
            suffix = 1
            while new_id in used:
                new_id = f"{base}-d{suffix}"
                suffix += 1
            group["group_id"] = new_id
            group_id = new_id
        elif not group_id:
            base = slugify_title_for_group_id(f"group-{i}", i)
            new_id = base
            suffix = 1
            while new_id in used:
                new_id = f"{base}-d{suffix}"
                suffix += 1
            group["group_id"] = new_id
            group_id = new_id
        used.add(group_id)


def file_key_basename(file_key: str) -> str:
    """Last path segment, lowercased (cross-platform)."""
    return (file_key or "").replace("\\", "/").rstrip("/").split("/")[-1].lower()


def is_manifest_file_key(file_key: str) -> bool:
    """True if ``file_key`` points at a dependency / lockfile by basename."""
    if not file_key or not str(file_key).strip():
        return False
    return file_key_basename(file_key) in _MANIFEST_BASENAMES


def best_file_key_for_finding(finding: dict, files: dict[str, str]) -> str:
    """Best-effort repo key for a finding: canonical path, or single inferred path."""
    if not isinstance(finding, dict):
        return ""
    resolved = resolve_path_to_canonical_key(finding.get("location", ""), files)
    if resolved:
        return resolved
    inferred = infer_paths_from_finding_text([finding], files, max_paths=1)
    return inferred[0] if inferred else ""


def group_mixes_manifest_and_code(
    finding_indices: list[int],
    findings: list[dict],
    files: dict[str, str],
) -> bool:
    """True if the given indices list both a manifest file and a non-manifest path."""
    has_manifest = False
    has_code = False
    for idx in finding_indices:
        if not isinstance(idx, int) or not (0 <= idx < len(findings)):
            continue
        file_key = best_file_key_for_finding(findings[idx], files)
        if is_manifest_file_key(file_key):
            has_manifest = True
        else:
            has_code = True
        if has_manifest and has_code:
            return True
    return False


def risk_level_for_finding_indices(findings: list[dict], finding_indices: list[int]) -> str:
    """Map severities in the batch to a single ``risk_level`` for FixGroup."""
    severities: list[str] = []
    for idx in finding_indices:
        if 0 <= idx < len(findings) and isinstance(findings[idx], dict):
            severities.append((findings[idx].get("severity") or "").lower())
    if any(severity in ("critical", "high") for severity in severities):
        return "high"
    if any(severity == "medium" for severity in severities):
        return "medium"
    return "low"


def _finding_text_blob_for_hints(group_findings: list[dict]) -> str:
    return " ".join(
        f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('fix', '')}"
        for finding in group_findings
        if isinstance(finding, dict)
    ).lower()


def expand_target_keys_for_group(
    group_findings: list[dict],
    files: dict[str, str],
    base_keys: list[str],
    max_files: int,
) -> list[str]:
    """Union planner ``target_files`` with every path resolved from the group's findings.

    The model often lists a single file while other findings in the same batch
    point elsewhere, which would leave route handlers out of the excerpt set.
    """
    merged: list[str] = []
    seen: set[str] = set()
    for file_key in base_keys:
        if file_key in files and file_key not in seen:
            merged.append(file_key)
            seen.add(file_key)
        if len(merged) >= max_files:
            return merged
    for file_key in resolve_paths_for_findings(group_findings, files):
        if file_key in files and file_key not in seen:
            merged.append(file_key)
            seen.add(file_key)
        if len(merged) >= max_files:
            break
    return merged


def supplement_api_like_targets(
    files: dict[str, str],
    group_findings: list[dict],
    keys: list[str],
    max_files: int,
) -> list[str]:
    """If findings read like HTTP/API issues but paths are sparse, add likely entry files."""
    if len(keys) >= min(5, max_files):
        return keys
    blob = _finding_text_blob_for_hints(group_findings)
    if not any(
        keyword in blob
        for keyword in (
            "api",
            "http",
            "rest",
            "endpoint",
            "route",
            "graphql",
            "injection",
            "cors",
            "rate limit",
            "csrf",
            "mass assignment",
            "idor",
        )
    ):
        return keys
    path_hints = (
        "routes",
        "router",
        "/api/",
        "handler",
        "controller",
        "views",
        "app.py",
        "main.py",
        "server",
        "fastapi",
        "flask",
        "express",
    )
    ordered: list[str] = list(dict.fromkeys(keys))
    seen: set[str] = set(ordered)
    scored_paths: list[tuple[int, str]] = []
    for repo_path in files:
        normalized = repo_path.replace("\\", "/").lower()
        score = sum(1 for hint in path_hints if hint in normalized)
        if score:
            scored_paths.append((score, repo_path))
    for _score, repo_path in sorted(
        scored_paths, key=lambda item: (-item[0], len(item[1]), item[1]),
    ):
        if repo_path not in seen:
            ordered.append(repo_path)
            seen.add(repo_path)
        if len(ordered) >= max_files:
            break
    return ordered


def resolve_target_files_for_group(
    raw_targets: list[str],
    group_findings: list[dict],
    files: dict[str, str],
) -> list[str]:
    """Merge explicit planner targets and finding ``location`` strings into real ``files`` keys."""
    keys: list[str] = []
    seen: set[str] = set()
    for target in raw_targets:
        file_key = resolve_path_to_canonical_key(target, files)
        if file_key and file_key not in seen:
            keys.append(file_key)
            seen.add(file_key)
    for finding in group_findings:
        file_key = resolve_path_to_canonical_key(finding.get("location", ""), files)
        if file_key and file_key not in seen:
            keys.append(file_key)
            seen.add(file_key)
    if not keys and group_findings:
        for file_key in infer_paths_from_finding_text(group_findings, files):
            if file_key not in seen:
                keys.append(file_key)
                seen.add(file_key)
    return keys


def rewrite_plan_target_files(
    groups: list[dict],
    findings: list[dict],
    files: dict[str, str],
) -> None:
    """Rewrite each group's ``target_files`` in place to valid keys in ``files``."""
    for group in groups:
        index_list = group.get("finding_indices") or []
        group_findings = [
            findings[index]
            for index in index_list
            if isinstance(index, int) and index < len(findings)
        ]
        raw = group.get("target_files") or []
        group["target_files"] = resolve_target_files_for_group(raw, group_findings, files)


def coerce_findings_into_groups(
    findings: list[dict],
    files: dict[str, str],
    max_per_group: int,
) -> list[dict[str, Any]]:
    """Split all findings into deterministic groups: one bucket per file / manifest / unresolved.

    Chunks of at most ``max_per_group`` are emitted when a single file has many findings.
    """
    finding_count = len(findings)
    if finding_count == 0:
        return []
    buckets: dict[tuple[str, str], list[int]] = defaultdict(list)
    for finding_index in range(finding_count):
        finding: dict = findings[finding_index] if isinstance(findings[finding_index], dict) else {}
        file_key = best_file_key_for_finding(finding, files)
        if is_manifest_file_key(file_key):
            bucket: tuple[str, str] = ("dep", file_key)
        elif file_key:
            bucket = ("code", file_key)
        else:
            bucket = ("unres", "unresolved")
        buckets[bucket].append(finding_index)
    for bucket_key in buckets:
        buckets[bucket_key].sort()
    dep_keys = sorted(
        (bucket for bucket in buckets if bucket[0] == "dep"),
        key=lambda item: item[1].lower(),
    )
    code_keys = sorted(
        (bucket for bucket in buckets if bucket[0] == "code"),
        key=lambda item: item[1].lower(),
    )
    unres_keys = [bucket for bucket in buckets if bucket[0] == "unres"]
    ordered_bucket_keys = dep_keys + code_keys + unres_keys
    groups: list[dict[str, Any]] = []
    used_group_ids: set[str] = set()
    for bucket_key in ordered_bucket_keys:
        index_list = buckets[bucket_key]
        kind, path = bucket_key
        for chunk_start in range(0, len(index_list), max_per_group):
            chunk = index_list[chunk_start : chunk_start + max_per_group]
            chunk_num = 1 + chunk_start // max_per_group
            first_finding = (
                findings[chunk[0]] if chunk and isinstance(findings[chunk[0]], dict) else {}
            )
            title = str(first_finding.get("title") or "security fix").strip()
            title_slug = slugify_title_for_group_id(title, chunk[0])
            if chunk_num > 1:
                base_group_id = f"{title_slug}-part{chunk_num}"
            else:
                base_group_id = title_slug
            group_id = base_group_id
            duplicate = 0
            while group_id in used_group_ids:
                duplicate += 1
                group_id = f"{base_group_id}-d{duplicate}"
            used_group_ids.add(group_id)
            groups.append(
                {
                    "group_id": group_id,
                    "label": (title or "security fix")[:220],
                    "finding_indices": chunk,
                    "target_files": [],
                    "risk_level": risk_level_for_finding_indices(findings, chunk),
                    "commit_message": f"fix(security): {title[:50]}",
                    "rationale": (
                        "Server-batched: max "
                        f"{max_per_group} findings per group; dependency files separate from code."
                    ),
                }
            )
    return groups


def plan_needs_coercion(
    groups: list[dict],
    findings: list[dict],
    files: dict[str, str],
    max_per_group: int,
) -> bool:
    """True when the LLM plan must be replaced by :func:`coerce_findings_into_groups`."""
    if not findings or len(findings) <= 1:
        return False
    total = len(findings)
    plan_groups = groups or []
    seen_indices: set[int] = set()
    for plan_group in plan_groups:
        for finding_index in plan_group.get("finding_indices") or []:
            if not isinstance(finding_index, int) or not (0 <= finding_index < total):
                return True
            if finding_index in seen_indices:
                return True
            seen_indices.add(finding_index)
    if seen_indices != set(range(total)):
        return True
    if len(plan_groups) == 1 and total > 1:
        return True
    for plan_group in plan_groups:
        index_list = [
            finding_index
            for finding_index in (plan_group.get("finding_indices") or [])
            if isinstance(finding_index, int) and 0 <= finding_index < total
        ]
        if len(index_list) > max_per_group:
            return True
        if group_mixes_manifest_and_code(index_list, findings, files):
            return True
    return False
