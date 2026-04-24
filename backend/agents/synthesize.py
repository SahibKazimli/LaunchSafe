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

from typing import Any

from core.config import SYNTH_MAX_TOKENS
from agents.prompts.executive_summary import (
    EXECUTIVE_SUMMARY_SYSTEM,
    format_executive_summary_user,
)
from .compliance_enrichment import coerce_compliance_item, enrich_compliance_list
from .runtime_log import emit
from .schemas import AuditReport, ComplianceRef, Finding, coerce_highlight_line_ranges
from tools.scanners import SEVERITY_DEFAULT_CVSS, infer_exposure_from_path

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _backfill_score_fields(raw: dict) -> dict:
    """Make sure every finding has cvss_base + exposure so compute_score
    has real numbers to work with even when the LLM omits them."""
    severity = str(raw.get("severity") or "low").lower()
    if not raw.get("exposure"):
        raw["exposure"] = infer_exposure_from_path(raw.get("location", ""))
    cvss_base = raw.get("cvss_base")
    try:
        cvss_base_f = float(cvss_base)
        if not (0.0 < cvss_base_f <= 10.0):
            raise ValueError
    except (TypeError, ValueError):
        raw["cvss_base"] = SEVERITY_DEFAULT_CVSS.get(severity, 0.0)
    return raw


def _sev_key(severity: str) -> int:
    return SEVERITY_RANK.get((severity or "low").lower(), 4)


def _normalize_loc(loc: str) -> str:
    return (loc or "").strip().lower().split(":", 1)[0]


def _dedupe(findings: list[dict]) -> list[Finding]:
    """Group by (lowercased title, file path). Keep the most severe copy
    and union its compliance refs."""
    findings_by_title_and_path: dict[tuple[str, str], dict] = {}

    for raw_finding in findings:
        if not isinstance(raw_finding, dict):
            continue
        if "_error" in raw_finding:
            continue
        title = (raw_finding.get("title") or "").strip().lower()
        file_path_key = _normalize_loc(raw_finding.get("location", ""))
        if not title:
            continue
        title_path_key = (title, file_path_key)

        existing_winner = findings_by_title_and_path.get(title_path_key)
        if existing_winner is None or _sev_key(raw_finding.get("severity")) < _sev_key(
            existing_winner.get("severity")
        ):
            merged_finding = dict(raw_finding)
        else:
            merged_finding = dict(existing_winner)

        by_compliance_id: dict[str, dict] = {}
        for ref in (raw_finding.get("compliance") or []) + (
            (existing_winner or {}).get("compliance") or []
        ):
            compliance_item = coerce_compliance_item(ref)
            if not compliance_item or not compliance_item["id"]:
                continue
            compliance_id = compliance_item["id"]
            if compliance_id not in by_compliance_id:
                by_compliance_id[compliance_id] = compliance_item
                continue
            previous = by_compliance_id[compliance_id]
            if (compliance_item.get("url")) and (not previous.get("url")):
                previous["url"] = compliance_item["url"]
            if len((compliance_item.get("summary") or "")) > len(
                (previous.get("summary") or "")
            ):
                previous["summary"] = compliance_item["summary"]
        merged_finding["compliance"] = list(by_compliance_id.values())

        findings_by_title_and_path[title_path_key] = merged_finding

    deduped_findings: list[Finding] = []
    for raw_finding in findings_by_title_and_path.values():
        raw_finding.pop("_branch", None)
        refs: list[ComplianceRef] = []
        for compliance_item in enrich_compliance_list(raw_finding.get("compliance") or []):
            try:
                refs.append(ComplianceRef.model_validate(compliance_item))
            except Exception:  
                # Tolerate partial refs; the report UI still shows id + link if present.
                refs.append(ComplianceRef.model_construct(
                    id=str(compliance_item.get("id")),
                    summary=str(compliance_item.get("summary") or ""),
                    url=compliance_item.get("url"),
                ))

        backfilled_finding = _backfill_score_fields(raw_finding)
        try:
            finding = Finding.model_validate({
                "severity": str(backfilled_finding.get("severity", "low")).lower() or "low",
                "module": backfilled_finding.get("module") or "general",
                "title": backfilled_finding.get("title") or "(untitled)",
                "location": backfilled_finding.get("location", ""),
                "description": backfilled_finding.get("description", ""),
                "fix": backfilled_finding.get("fix", ""),
                "priority": max(1, min(5, int(backfilled_finding.get("priority") or 3))),
                "is_true_positive": bool(
                    backfilled_finding.get("is_true_positive", True)
                ),
                "rationale": backfilled_finding.get("rationale"),
                "compliance": refs,
                "cvss_base": float(backfilled_finding.get("cvss_base") or 0.0),
                "exposure": backfilled_finding.get("exposure") or "production",
                "highlight_line_ranges": coerce_highlight_line_ranges(
                    backfilled_finding.get("highlight_line_ranges")
                ),
            })
            deduped_findings.append(finding)
        except Exception:  
            continue

    deduped_findings.sort(
        key=lambda item: (_sev_key(item.severity), item.priority)
    )
    return deduped_findings


def _branch_breakdown(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        if isinstance(finding, dict):
            branch = finding.get("_branch", "general")
            counts[branch] = counts.get(branch, 0) + 1
    return counts


def _heuristic_risk(findings: list[Finding]) -> str:
    severities = [finding.severity.lower() for finding in findings if finding.is_true_positive]
    if any(severity == "critical" for severity in severities): return "critical"
    if sum(1 for severity in severities if severity == "high") >= 3: return "high"
    if any(severity == "high" for severity in severities):  return "high"
    if sum(1 for severity in severities if severity == "medium") >= 4: return "medium"
    if any(severity == "medium" for severity in severities): return "medium"
    if severities: return "low"
    return "minimal"


def _heuristic_summary(target: str, findings: list[Finding], branches: dict[str, int]) -> str:
    if not findings:
        return f"No exploitable issues found in {target} across {sum(branches.values()) or 0} specialist passes."
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[finding.severity.lower()] = counts.get(finding.severity.lower(), 0) + 1
    parts = [f"{count} {severity}" for severity, count in counts.items() if count]
    branch_list = ", ".join(sorted(branches.keys())) or "general"
    return (
        f"Audit of {target} surfaced {len(findings)} issue(s) "
        f"({', '.join(parts)}). Coverage: {branch_list}."
    )


def _heuristic_top_fixes(findings: list[Finding]) -> list[str]:
    out: list[str] = []
    for finding in findings:
        if not finding.is_true_positive:
            continue
        if finding.severity.lower() not in ("critical", "high"):
            continue
        out.append(finding.fix.strip() or finding.title)
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
        from agents.llm import get_llm
    except Exception:
        return None

    rendered = []
    for finding in findings[:30]:
        rendered.append(
            f"- [{finding.severity}] {finding.title} @ {finding.location} (priority {finding.priority})\n"
            f"  fix: {finding.fix.strip()[:200]}"
        )
    body = "\n".join(rendered)

    system = EXECUTIVE_SUMMARY_SYSTEM
    user = format_executive_summary_user(target, branches, len(findings), body)

    try:
        llm = get_llm(max_tokens=SYNTH_MAX_TOKENS)
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
    except Exception:
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
