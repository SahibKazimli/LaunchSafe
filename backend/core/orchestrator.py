"""Scan orchestration — drives the LangGraph pipeline or regex fallback.

Extracted from ``main.py`` so the API routes don't contain business logic.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from agents.runtime_log import emit
from tools.scanners import (
    compute_score,
    scan_api,
    scan_auth,
    scan_cloud,
    scan_dependencies,
    scan_privacy,
    scan_secrets,
)
from core import scan_store as _ss


async def run_scan(scan_id: str, files: dict[str, str]) -> None:
    """Drive the LangGraph multi-agent pipeline end-to-end.

    Topology lives in ``agents/graph.py``::

        recon -> [general/payments/iac/auth/cicd in parallel] -> synthesize.

    Each node logs branch-tagged events via the shared event-bus
    (``agents.runtime_log``), so the frontend just polls ``scan-status``
    and renders whatever it finds.

    Falls back to a pure-regex scan if ``ANTHROPIC_API_KEY`` is missing.
    """
    _ss.mark_running(scan_id)
    scan = _ss.get_scan(scan_id)
    if scan is None:
        return

    emit(scan_id, "info", f"Starting scan of {len(files)} files", branch="outer")

    if not os.environ.get("GOOGLE_API_KEY") and not os.environ.get("ANTHROPIC_API_KEY"):
        emit(scan_id, "warn", "No ANTHROPIC_API_KEY — regex-only fallback", branch="outer")
        await _run_regex_fallback(scan_id, files)
        return

    final_state: dict | None = None
    try:
        from agents.graph import get_agent

        agent = get_agent()
        initial: dict[str, Any] = {
            "messages": [],
            "files": files,
            "scan_id": scan_id,
            "target": scan["target"],
            "branch_findings": [],
        }

        async for state in agent.astream(initial, stream_mode="values"):
            if isinstance(state, dict):
                final_state = state
                profile = state.get("repo_profile")
                if profile and not scan.get("repo_profile"):
                    _ss.update_scan(scan_id, repo_profile=profile)

        report = (final_state or {}).get("structured_response")
        report_findings: list[dict] = []
        summary = ""
        top_fixes: list[str] = []
        overall_risk = ""

        if report is not None:
            try:
                report_findings = [
                    f.model_dump() for f in getattr(report, "findings", []) or []
                ]
                summary = getattr(report, "summary", "") or ""
                top_fixes = list(getattr(report, "top_fixes", []) or [])
                overall_risk = getattr(report, "overall_risk", "") or ""
            except Exception:
                pass

        # Salvage branch findings if synthesize produced nothing
        salvaged = [
            f
            for f in (final_state or {}).get("branch_findings", []) or []
            if isinstance(f, dict) and "_error" not in f
        ]
        if not report_findings and salvaged:
            emit(
                scan_id,
                "warn",
                f"Synthesize produced no report — salvaging {len(salvaged)} branch findings",
                branch="outer",
            )
            report_findings = salvaged

        if not summary and report_findings:
            summary = (
                f"Audit complete. {len(report_findings)} finding(s) across "
                f"{len(scan.get('branches', {}))} specialist branches."
            )

        score, grade = compute_score(report_findings)
        _ss.update_scan(
            scan_id,
            status="done",
            findings=report_findings,
            score=score,
            grade=grade,
            summary=summary,
            top_fixes=top_fixes,
            overall_risk=overall_risk or ("high" if grade in ("D", "F") else "medium"),
        )

    except Exception as exc:  # noqa: BLE001
        salvaged: list[dict] = []
        try:
            salvaged = [
                f
                for f in (final_state or {}).get("branch_findings", []) or []
                if isinstance(f, dict) and "_error" not in f
            ]
        except Exception:
            pass

        if salvaged:
            emit(
                scan_id,
                "warn",
                f"Pipeline crashed, but salvaged {len(salvaged)} branch findings.",
                branch="outer",
            )
            score, grade = compute_score(salvaged)
            _ss.update_scan(
                scan_id,
                status="done",
                findings=salvaged,
                score=score,
                grade=grade,
                summary=(
                    f"Pipeline crashed before synthesize ({str(exc)[:120]}). "
                    f"Showing {len(salvaged)} findings collected during the scan."
                ),
                top_fixes=[],
                overall_risk="high" if grade in ("D", "F") else "medium",
            )
        else:
            _ss.update_scan(scan_id, status="error", error=str(exc)[:500])


async def _run_regex_fallback(scan_id: str, files: dict[str, str]) -> None:
    """Pure-deterministic scan used when no Anthropic key is configured."""
    import time as _time

    scan = _ss.get_scan(scan_id)
    if scan is None:
        return

    if not scan.get("started_at"):
        _ss.update_scan(scan_id, started_at=_time.time())

    all_findings: list[dict] = []
    module_fns = [
        ("secrets", "Secret detection",     scan_secrets),
        ("auth",    "Auth & access review", scan_auth),
        ("api",     "API security review",  scan_api),
        ("cloud",   "Cloud config audit",   scan_cloud),
        ("privacy", "Privacy & compliance", scan_privacy),
        ("deps",    "Dependency scanning",  scan_dependencies),
    ]
    for mod_id, mod_name, fn in module_fns:
        await asyncio.sleep(0.6)
        results = fn(files)
        all_findings.extend(results)
        scan.setdefault("modules_done", []).append(
            {"id": mod_id, "name": mod_name, "count": len(results)}
        )
        _ss.update_scan(scan_id, findings=list(all_findings))

    score, grade = compute_score(all_findings)
    _ss.update_scan(
        scan_id,
        status="done",
        score=score,
        grade=grade,
        findings=all_findings,
        summary=(
            "Regex-only fallback scan (no ANTHROPIC_API_KEY set). "
            f"Found {len(all_findings)} issues across 6 modules."
        ),
        top_fixes=[],
        overall_risk="high" if grade in ("D", "F") else "medium",
    )
