"""FastAPI route handlers for LaunchSafe.

All HTTP endpoints live here.  ``main.py`` includes the router during
app bootstrap via ``app.include_router(router)``.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import uuid

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from core.config import EVENT_API_TAIL
from tools.ingest import clone_github, extract_zip
from tools.scanners import compute_score, score_breakdown
from core import scan_store as _ss

_HERE = Path(__file__).resolve().parent          # backend/core/
_BACKEND = _HERE.parent                          # backend/
_FRONTEND = (_BACKEND.parent / "frontend").resolve()
_FRONTEND_DIST = (_FRONTEND / "dist").resolve()

templates = Jinja2Templates(directory=str(_FRONTEND))


def _dist_page(name: str) -> FileResponse | None:
    path = _FRONTEND_DIST / name
    return FileResponse(path) if path.is_file() else None

router = APIRouter()


# Pages
@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    built = _dist_page("index.html")
    if built is not None:
        return built
    return templates.TemplateResponse(request, "index.html")


@router.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_page(request: Request, scan_id: str):
    if not _ss.exists(scan_id):
        return HTMLResponse("Scan not found", status_code=404)
    built = _dist_page("scan.html")
    if built is not None:
        return built
    return templates.TemplateResponse(request, "scan.html", {"scan_id": scan_id})


@router.get("/report/{scan_id}", response_class=HTMLResponse)
async def report_page(request: Request, scan_id: str):
    scan = _ss.get_scan(scan_id)
    if not scan or scan["status"] != "done":
        return HTMLResponse("Report not ready", status_code=404)

    built = _dist_page("report.html")
    if built is not None:
        return built

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
        enriched.append(ef)
    return templates.TemplateResponse(request, "report.html", {
        "scan": {**scan, "id": scan_id},
        "findings": enriched,
        "counts": counts,
        "total": len(findings),
    })



# API

@router.post("/start-scan")
async def start_scan(
    file: UploadFile = File(None),
    github_url: str = Form(""),
):
    from core.orchestrator import run_scan

    scan_id = str(uuid.uuid4())[:8]
    target = github_url.strip() or (file.filename if file else "uploaded file")
    _ss.create_scan(scan_id, target)

    files: dict[str, str] = {}
    user_provided_input = bool(github_url.strip()) or bool(file and file.filename)

    if github_url.strip():
        try:
            files = await asyncio.to_thread(clone_github, github_url.strip())
        except Exception as exc:  
            _ss.update_scan(
                scan_id,
                status="error",
                error=f"Failed to clone {github_url}: {exc!s}",
            )
            return {"scan_id": scan_id}

    elif file and file.filename:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name
        files = extract_zip(tmp_path)
        os.unlink(tmp_path)

    if user_provided_input and not files:
        _ss.update_scan(
            scan_id,
            status="error",
            error=(
                "Repo cloned but no scannable files found. Supported extensions "
                "include .py .js .ts .go .rs .c .h .cpp .java .md .yaml .tf and "
                "files like Makefile / Dockerfile / README. Check that the repo "
                "is public and contains source code."
            ),
        )
        return {"scan_id": scan_id}

    if not files:
        files = _demo_files()

    # Stash sources on the scan record immediately so fix mode always has
    # file blobs even if orchestrator behavior changes later.
    _ss.update_scan(scan_id, _files=files)

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
    new_events = [event for event in all_events if event.get("seq", 0) > since]
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
        findings = [finding for finding in findings if finding["severity"] == severity]
    return {"findings": findings}



# Fix Session API


from pydantic import BaseModel as _PydanticBase
from core import fix_store as _fs


class _StartFixRequest(_PydanticBase):
    scan_id: str
    finding_indices: list[int] = []


@router.post("/start-fix")
async def start_fix(req: _StartFixRequest):
    from core.fix_orchestrator import run_fix_session

    if not _ss.exists(req.scan_id):
        return {"error": "scan not found"}

    fix_id = str(uuid.uuid4())[:8]
    _fs.create_fix_session(fix_id, req.scan_id, req.finding_indices)
    scan_for_fix = _ss.get_scan(req.scan_id) or {}
    findings_full = list(scan_for_fix.get("findings") or [])
    _fs.update_fix_session(
        fix_id,
        snapshot_files=dict(scan_for_fix.get("_files") or {}),
        snapshot_finding_files=dict(scan_for_fix.get("finding_files") or {}),
        report_findings_full=findings_full,
        report_summary=str(scan_for_fix.get("summary") or ""),
        report_grade=str(scan_for_fix.get("grade") or ""),
        report_top_fixes=list(scan_for_fix.get("top_fixes") or []),
        report_overall_risk=str(scan_for_fix.get("overall_risk") or ""),
    )

    asyncio.create_task(run_fix_session(fix_id, req.scan_id, req.finding_indices))
    return {"fix_id": fix_id}


@router.get("/fix-status/{fix_id}")
async def fix_status(fix_id: str):
    session = _fs.get_fix_session(fix_id)
    if not session:
        return {"error": "not found"}

    return {
        "status": session["status"],
        "scan_id": session.get("scan_id", ""),
        "fix_plan": session.get("fix_plan"),
        "patches": session.get("patches", []),
        "review": session.get("review"),
        "error": session.get("error"),
        "events": session.get("events", [])[-50:],
    }


@router.get("/fix-patches/{fix_id}")
async def fix_patches(fix_id: str):
    session = _fs.get_fix_session(fix_id)
    if not session:
        return {"error": "not found"}
    return {
        "patches": session.get("patches", []),
        "review": session.get("review"),
        "fix_plan": session.get("fix_plan"),
    }


@router.get("/fix/{fix_id}", response_class=HTMLResponse)
async def fix_page(request: Request, fix_id: str):
    if not _fs.exists(fix_id):
        return HTMLResponse("Fix session not found", status_code=404)
    built = _dist_page("fix.html")
    if built is not None:
        return built
    session = _fs.get_fix_session(fix_id)
    scan_id = session.get("scan_id", "") if session else ""
    return templates.TemplateResponse(request, "fix.html", {
        "fix_id": fix_id,
        "scan_id": scan_id,
    })


@router.get("/debug/fix/{fix_id}")
async def debug_fix(fix_id: str):
    """Raw dump of a fix session — diagnose patch generation issues."""
    session = _fs.get_fix_session(fix_id)
    if not session:
        return {"error": "not found"}
    patches = session.get("patches", [])
    return {
        "status": session.get("status"),
        "error": session.get("error"),
        "finding_indices": session.get("finding_indices"),
        "fix_plan_groups": len((session.get("fix_plan") or {}).get("groups", [])),
        "patch_groups": len(patches),
        "patches_per_group": [
            {"group_id": p.get("group_id"), "patch_count": len(p.get("patches", [])), "notes": p.get("notes", "")}
            for p in patches
        ],
        "review_approved": (session.get("review") or {}).get("approved"),
        "review_notes": (session.get("review") or {}).get("notes"),
        "snapshot_files_count": len(session.get("snapshot_files") or {}),
        "snapshot_finding_files_count": len(session.get("snapshot_finding_files") or {}),
        "events": session.get("events", []),
    }


@router.get("/debug/scan/{scan_id}")
async def debug_scan(scan_id: str):
    """Check what a scan stored — especially whether _files was stashed."""
    scan = _ss.get_scan(scan_id)
    if not scan:
        return {"error": "not found"}
    files = scan.get("_files", {})
    ffb = scan.get("finding_files") or {}
    findings = scan.get("findings", [])
    return {
        "status": scan.get("status"),
        "finding_count": len(findings),
        "findings_severity": [f.get("severity") for f in findings],
        "finding_locations_sample": [f.get("location") for f in findings[:15]],
        "files_stashed": len(files),
        "finding_files_bundle_count": len(ffb),
        "finding_files_bundle_keys": list(ffb.keys())[:20],
        "file_keys": list(files.keys())[:20],
    }


