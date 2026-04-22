"""FastAPI route handlers for LaunchSafe.

All HTTP endpoints live here.  ``main.py`` includes the router during
app bootstrap via ``app.include_router(router)``.
"""

from __future__ import annotations

import asyncio
import uuid
import re

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from core.config import EVENT_API_TAIL
from tools.ingest import clone_github
from tools.scanners import score_breakdown
from core import scan_store as _ss

_HERE = Path(__file__).resolve().parent          # backend/core/
_BACKEND = _HERE.parent                          # backend/
_FRONTEND = (_BACKEND.parent / "frontend").resolve()

templates = Jinja2Templates(directory=str(_FRONTEND))

router = APIRouter()

_OWASP_TAG_URLS = {
    "OWASP A01:2021": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "OWASP A02:2021": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "OWASP A03:2021": "https://owasp.org/Top10/A03_2021-Injection/",
    "OWASP A04:2021": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    "OWASP A05:2021": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "OWASP A06:2021": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    "OWASP A07:2021": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    "OWASP A08:2021": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    "OWASP A09:2021": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    "OWASP A10:2021": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
}


def _normalize_owasp_id(raw_id: str) -> str:
    s = (raw_id or "").strip().upper().replace("-", " ")
    m = re.search(r"OWASP\s+A0?(10|[1-9])", s)
    if not m:
        return ""
    num = int(m.group(1))
    if num < 1 or num > 10:
        return ""
    return f"OWASP A{num:02d}:2021"


def _fallback_compliance_url(tag_id: str) -> str | None:
    canonical = _normalize_owasp_id(tag_id)
    if canonical:
        return _OWASP_TAG_URLS.get(canonical)
    return None


def _normalize_compliance_tags(raw_tags: list) -> list:
    out = []
    for tag in raw_tags or []:
        if hasattr(tag, "model_dump"):
            try:
                tag = tag.model_dump()
            except Exception:
                pass
        if isinstance(tag, dict):
            tid = str(tag.get("id") or "").strip()
            if not tid:
                continue
            raw_u = tag.get("url") or tag.get("link")
            u = str(raw_u).strip() if raw_u else ""
            out.append({
                "id": tid,
                "summary": str(tag.get("summary") or "").strip(),
                "url": u or _fallback_compliance_url(tid),
            })
        elif hasattr(tag, "id"):
            tid = str(getattr(tag, "id", "") or "").strip()
            if not tid:
                continue
            raw_u = getattr(tag, "url", None) or getattr(tag, "link", None)
            u = str(raw_u).strip() if raw_u else ""
            out.append({
                "id": tid,
                "summary": str(getattr(tag, "summary", "") or "").strip(),
                "url": u or _fallback_compliance_url(tid),
            })
        elif isinstance(tag, str):
            tid = tag.strip()
            if not tid:
                continue
            out.append({
                "id": tid,
                "summary": "",
                "url": _fallback_compliance_url(tid),
            })
    return out


# Pages
@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


@router.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_page(request: Request, scan_id: str):
    if not _ss.exists(scan_id):
        return HTMLResponse("Scan not found", status_code=404)
    return templates.TemplateResponse(request, "scan.html", {"scan_id": scan_id})


@router.get("/report/{scan_id}", response_class=HTMLResponse)
async def report_page(request: Request, scan_id: str):
    scan = _ss.get_scan(scan_id)
    if not scan or scan["status"] != "done":
        return HTMLResponse("Report not ready", status_code=404)

    findings = scan["findings"]
    counts = {
        "critical": sum(1 for finding in findings if finding["severity"] == "critical"),
        "high":     sum(1 for finding in findings if finding["severity"] == "high"),
        "medium":   sum(1 for finding in findings if finding["severity"] == "medium"),
        "low":      sum(1 for finding in findings if finding["severity"] == "low"),
    }
    breakdown = score_breakdown(findings)
    enriched: list[dict] = []
    for finding, row in zip(findings, breakdown["rows"]):
        ef = dict(finding)
        ef["_score"] = row
        ef["compliance"] = _normalize_compliance_tags(ef.get("compliance", []))
        enriched.append(ef)
    return templates.TemplateResponse(request, "report.html", {
        "scan": scan,
        "findings": enriched,
        "counts": counts,
        "total": len(findings),
        "breakdown": breakdown,
    })



# API

@router.post("/start-scan")
async def start_scan(github_url: str = Form("")):
    from core.orchestrator import run_scan

    url = (github_url or "").strip()
    if not url:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Paste a public GitHub repository URL to start a scan.",
            },
        )

    scan_id = str(uuid.uuid4())[:8]
    _ss.create_scan(scan_id, url)

    files: dict[str, str] = {}
    try:
        files = await asyncio.to_thread(clone_github, url)
    except Exception as exc:
        _ss.update_scan(
            scan_id,
            status="error",
            error=f"Failed to clone {url}: {exc!s}",
        )
        return {"scan_id": scan_id}

    if not files:
        _ss.update_scan(
            scan_id,
            status="error",
            error="Repo cloned but no scannable files found.",
        )
        return {"scan_id": scan_id}

    asyncio.create_task(run_scan(scan_id, files))
    return {"scan_id": scan_id}

@router.get("/scan-status/{scan_id}")
async def scan_status(scan_id: str, since: int = 0):
    scan = _ss.get_scan(scan_id)
    if not scan:
        return {"error": "not found"}

    profile = scan.get("repo_profile")
    if hasattr(profile, "model_dump"):
        profile = profile.model_dump()

    all_events = scan.get("events", [])
    new_events = [e for e in all_events if e.get("seq", 0) > since]
    if len(new_events) > EVENT_API_TAIL:
        new_events = new_events[-EVENT_API_TAIL:]
    last_seq = scan.get("event_seq", 0)

    return {
        "status": scan["status"],
        "target": scan.get("target", ""),
        "modules_done": scan.get("modules_done", []),
        "branches": scan.get("branches", {}),
        "findings_count": len(scan.get("findings", [])),
        "repo_profile": profile,
        "summary": scan.get("summary", ""),
        "overall_risk": scan.get("overall_risk", ""),
        "events": new_events,
        "last_seq": last_seq,
        "error": scan.get("error"),
    }


@router.get("/api/findings/{scan_id}")
async def get_findings(scan_id: str, severity: str = "all"):
    scan = _ss.get_scan(scan_id)
    if not scan:
        return {"error": "not found"}
    findings = scan.get("findings", [])
    if severity != "all":
        findings = [f for f in findings if f["severity"] == severity]
    out: list[dict] = []
    for f in findings:
        row = dict(f)
        row["compliance"] = _normalize_compliance_tags(row.get("compliance", []))
        out.append(row)
    return {"findings": out}
