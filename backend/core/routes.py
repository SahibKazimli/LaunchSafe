"""FastAPI route handlers for LaunchSafe.

All HTTP endpoints live here.  ``main.py`` includes the router during
app bootstrap via ``app.include_router(router)``.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import uuid
import re

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from core.config import EVENT_API_TAIL
from tools.ingest import clone_github
from tools.scanners import compute_score, score_breakdown
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
            out.append({
                "id": tid,
                "summary": str(tag.get("summary") or "").strip(),
                "url": tag.get("url") or _fallback_compliance_url(tid),
            })
        elif hasattr(tag, "id"):
            tid = str(getattr(tag, "id", "") or "").strip()
            if not tid:
                continue
            out.append({
                "id": tid,
                "summary": str(getattr(tag, "summary", "") or "").strip(),
                "url": getattr(tag, "url", None) or _fallback_compliance_url(tid),
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

    # GitHub flow
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

    # ZIP upload flow (YOU DID NOT REMOVE THIS BEFORE)
    elif file and file.filename:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name

        files = extract_zip(tmp_path)
        os.unlink(tmp_path)

    # fallback handling
    if user_provided_input and not files:
        _ss.update_scan(
            scan_id,
            status="error",
            error="Repo cloned but no scannable files found.",
        )
        return {"scan_id": scan_id}

    if not files:
        files = _demo_files()

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
    session = _fs.get_fix_session(fix_id)
    scan_id = session.get("scan_id", "") if session else ""
    return templates.TemplateResponse(request, "fix.html", {
        "fix_id": fix_id,
        "scan_id": scan_id,
    })



# Demo / fallback data


def _demo_files() -> dict[str, str]:
    """Demo files with intentional vulnerabilities for demonstration."""
    return {
        "src/config/aws.js": """
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
module.exports = { AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY };
""",
        ".env.example": """
STRIPE_SECRET_KEY=sk_live_51ABC123realkey
DATABASE_URL=postgres://admin:password123@db.example.com/prod
SECRET_KEY=short
DEBUG=True
""",
        "middleware/auth.js": """
const jwt = require('jsonwebtoken');
function verify(token) {
    return jwt.verify(token, process.env.SECRET_KEY); // no algorithm specified
}
function hashPassword(pw) {
    return md5(pw); // insecure
}
""",
        "routes/api.js": """
const express = require('express');
const app = express();
const cors = require('cors');
app.use(cors({ origin: '*' }));

app.post('/login', (req, res) => {
    const query = \"SELECT * FROM users WHERE email = '\" + req.body.email + \"'\";
    db.execute(query);
});
app.get('/admin/users', (req, res) => {
    // no auth middleware!
    res.json(db.query('SELECT * FROM users'));
});
""",
        "terraform/main.tf": """
resource "aws_s3_bucket" "uploads" {
  bucket = "my-startup-uploads"
  acl    = "public-read"
}
resource "aws_db_instance" "main" {
  publicly_accessible = true
  password            = "mysupersecret123"
}
resource "aws_security_group_rule" "ssh" {
  cidr_blocks = ["0.0.0.0/0"]
  from_port   = 22
}
""",
        "package.json": """
{
  "dependencies": {
    "lodash": "4.17.20",
    "jsonwebtoken": "8.5.0",
    "express": "4.17.1",
    "axios": "0.21.0"
  }
}
""",
        "models/user.py": """
import hashlib
class User:
    def set_password(self, pw):
        self.password_hash = hashlib.md5(pw.encode()).hexdigest()
    def log_login(self, email):
        print(f"Login attempt: {email}")  # PII in logs
    ssn = models.CharField(max_length=11)  # PII field
""",
    }
