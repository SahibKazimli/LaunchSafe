"""Synthesize node: merge specialist findings into the final AuditReport.

Runs once after all specialist branches converge. Responsibilities:

  1. Read branch_findings (already list-concat-merged by the reducer).
  2. Filter out tombstone error markers, dedupe near-duplicates across
     branches, and re-sort by severity / priority.
  3. Ask Claude to write the executive summary, top fixes, and overall
     risk band — based on the deduped findings only.
  4. Emit the final `AuditReport` as `structured_response`, which is
     what `main.py` reads when the graph completes.

This module deliberately does NOT call any tools or do any new scanning;
it is pure post-processing + a single LLM call.
"""

from __future__ import annotations

import os
from typing import Any

from .runtime_log import emit
from .schemas import AuditReport, ComplianceRef, Finding
from .tools.scanners import SEVERITY_DEFAULT_CVSS, infer_exposure_from_path

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _backfill_score_fields(raw: dict) -> dict:
    """Make sure every finding has cvss_base + exposure so compute_score
    has real numbers to work with even when the LLM omits them."""
    sev = str(raw.get("severity") or "low").lower()
    if not raw.get("exposure"):
        raw["exposure"] = infer_exposure_from_path(raw.get("location", ""))
    cb = raw.get("cvss_base")
    try:
        cb_f = float(cb)
        if not (0.0 < cb_f <= 10.0):
            raise ValueError
    except (TypeError, ValueError):
        raw["cvss_base"] = SEVERITY_DEFAULT_CVSS.get(sev, 0.0)
    return raw


def _sev_key(sev: str) -> int:
    return SEVERITY_RANK.get((sev or "low").lower(), 4)


def _normalize_loc(loc: str) -> str:
    return (loc or "").strip().lower().split(":", 1)[0]


def _dedupe(findings: list[dict]) -> list[Finding]:
    """Group by (lowercased title, file path). Keep the most severe copy
    and union its compliance refs."""
    by_key: dict[tuple[str, str], dict] = {}

    for raw in findings:
        if not isinstance(raw, dict):
            continue
        if "_error" in raw:
            continue
        title = (raw.get("title") or "").strip().lower()
        loc = _normalize_loc(raw.get("location", ""))
        if not title:
            continue
        key = (title, loc)

        winner = by_key.get(key)
        if winner is None or _sev_key(raw.get("severity")) < _sev_key(winner.get("severity")):
            keep = dict(raw)
        else:
            keep = dict(winner)

        merged_refs: list[dict] = []
        seen: set[str] = set()
        for r in (raw.get("compliance") or []) + ((winner or {}).get("compliance") or []):
            if not isinstance(r, dict):
                continue
            rid = r.get("id")
            if not rid or rid in seen:
                continue
            seen.add(rid)
            merged_refs.append(r)
        keep["compliance"] = merged_refs

        by_key[key] = keep

    out: list[Finding] = []
    for raw in by_key.values():
        raw.pop("_branch", None)
        refs: list[ComplianceRef] = []
        for r in raw.get("compliance") or []:
            if not isinstance(r, dict) or not r.get("id"):
                continue
            try:
                refs.append(ComplianceRef.model_validate(r))
            except Exception:  
                # Tolerate partial refs (e.g. id-only); the popover will
                # still render the id even without a summary.
                refs.append(ComplianceRef.model_construct(
                    id=str(r.get("id")),
                    summary=str(r.get("summary") or ""),
                    url=r.get("url"),
                ))

        backfilled = _backfill_score_fields(raw)
        try:
            f = Finding.model_validate({
                "severity": str(backfilled.get("severity", "low")).lower() or "low",
                "module": backfilled.get("module") or "general",
                "title": backfilled.get("title") or "(untitled)",
                "location": backfilled.get("location", ""),
                "description": backfilled.get("description", ""),
                "fix": backfilled.get("fix", ""),
                "priority": max(1, min(5, int(backfilled.get("priority") or 3))),
                "is_true_positive": bool(backfilled.get("is_true_positive", True)),
                "rationale": backfilled.get("rationale"),
                "compliance": refs,
                "cvss_base": float(backfilled.get("cvss_base") or 0.0),
                "exposure": backfilled.get("exposure") or "production",
            })
            out.append(f)
        except Exception:  
            continue

    out.sort(key=lambda x: (_sev_key(x.severity), x.priority))
    return out


def _branch_breakdown(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        if isinstance(f, dict):
            b = f.get("_branch", "general")
            counts[b] = counts.get(b, 0) + 1
    return counts


def _heuristic_risk(findings: list[Finding]) -> str:
    sev = [f.severity.lower() for f in findings if f.is_true_positive]
    if any(s == "critical" for s in sev): return "critical"
    if sum(1 for s in sev if s == "high") >= 3: return "high"
    if any(s == "high" for s in sev):  return "high"
    if sum(1 for s in sev if s == "medium") >= 4: return "medium"
    if any(s == "medium" for s in sev): return "medium"
    if sev: return "low"
    return "minimal"


def _heuristic_summary(target: str, findings: list[Finding], branches: dict[str, int]) -> str:
    if not findings:
        return f"No exploitable issues found in {target} across {sum(branches.values()) or 0} specialist passes."
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity.lower()] = counts.get(f.severity.lower(), 0) + 1
    parts = [f"{n} {sev}" for sev, n in counts.items() if n]
    branch_list = ", ".join(sorted(branches.keys())) or "general"
    return (
        f"Audit of {target} surfaced {len(findings)} issue(s) "
        f"({', '.join(parts)}). Coverage: {branch_list}."
    )


def _heuristic_top_fixes(findings: list[Finding]) -> list[str]:
    out: list[str] = []
    for f in findings:
        if not f.is_true_positive:
            continue
        if f.severity.lower() not in ("critical", "high"):
            continue
        out.append(f.fix.strip() or f.title)
        if len(out) >= 5:
            break
    return out



# LLM-assisted summary 


def _llm_summary(target: str, findings: list[Finding], branches: dict[str, int]):
    """Ask Claude for a clean exec summary + top fixes + overall risk.

    Returns (summary, top_fixes, overall_risk) or None on failure.
    """
    if not findings:
        return (
            _heuristic_summary(target, findings, branches),
            [],
            "minimal",
        )

    try:
        from langchain_anthropic import ChatAnthropic
    except Exception:  
        return None

    rendered = []
    for f in findings[:30]:
        rendered.append(
            f"- [{f.severity}] {f.title} @ {f.location} (priority {f.priority})\n"
            f"  fix: {f.fix.strip()[:200]}"
        )
    body = "\n".join(rendered)

    system = (
        "You are the lead security auditor writing the executive summary "
        "of a startup security audit. The findings have already been "
        "produced by specialist sub-agents and deduped. Do NOT invent new "
        "findings. Keep `findings` EXACTLY as provided by the input "
        "JSON below — copy the list verbatim into your response.\n\n"
        "Your only original output is:\n"
        "  - summary: 2-4 sentences for a non-technical founder. State "
        "    the headline risk and what enterprise customers / regulators "
        "    will care about. Plain English.\n"
        "  - top_fixes: 3-5 imperative one-liners. What to do Monday "
        "    morning, in priority order. Pull from the findings' `fix` "
        "    fields.\n"
        "  - overall_risk: one of critical / high / medium / low / minimal. "
        "    Use the calibration anchors: any critical finding -> 'critical'; "
        "    >=3 high or one critical-adjacent pattern -> 'high'; etc.\n"
    )
    user = (
        f"Target: {target}\n"
        f"Specialist coverage: {branches}\n"
        f"Total findings (after dedup): {len(findings)}\n\n"
        f"FINDINGS:\n{body}\n"
    )

    try:
        model_name = os.environ.get("LAUNCHSAFE_LLM_MODEL", "claude-sonnet-4-5")
        llm = ChatAnthropic(model=model_name, max_tokens=2048, temperature=0)
        structured = llm.with_structured_output(AuditReport)
        result: AuditReport = structured.invoke(
            [{"role": "system", "content": system},
             {"role": "user", "content": user}]
        )
        return (
            result.summary or _heuristic_summary(target, findings, branches),
            result.top_fixes or _heuristic_top_fixes(findings),
            result.overall_risk or _heuristic_risk(findings),
        )
    except Exception:  # noqa: BLE001
        return None



# Public node


def synthesize_node(state: dict[str, Any]) -> dict[str, Any]:
    scan_id = state.get("scan_id", "")
    raw_findings = state.get("branch_findings") or []
    target = state.get("target", "the repository")

    branches = _branch_breakdown(raw_findings)
    branch_summary = ", ".join(f"{b}={n}" for b, n in branches.items()) or "none"
    emit(
        scan_id,
        "branch_start",
        f"synthesize: merging {len(raw_findings)} findings ({branch_summary})",
        branch="synthesize",
    )

    deduped = _dedupe(raw_findings)
    emit(
        scan_id,
        "info",
        f"deduped {len(raw_findings)} → {len(deduped)} unique findings",
        branch="synthesize",
    )

    llm_out = _llm_summary(target, deduped, branches)
    if llm_out is None:
        summary = _heuristic_summary(target, deduped, branches)
        top_fixes = _heuristic_top_fixes(deduped)
        overall_risk = _heuristic_risk(deduped)
        emit(scan_id, "warn", "LLM summary failed; used heuristic fallback", branch="synthesize")
    else:
        summary, top_fixes, overall_risk = llm_out

    report = AuditReport(
        summary=summary,
        findings=deduped,
        top_fixes=top_fixes,
        overall_risk=overall_risk,
    )

    emit(
        scan_id,
        "branch_done",
        f"synthesize complete: {len(deduped)} findings, risk={overall_risk}",
        branch="synthesize",
    )

    return {"structured_response": report}
