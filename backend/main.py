"""
LaunchSafe — Startup Security Auditor
FastAPI backend + single LangGraph ReAct agent powered by Claude.
Run: uvicorn main:app --reload
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from agents.runtime_log import set_event_sink
from agents.tools.ingest import clone_github, extract_zip
from agents.tools.scanners import (
    compute_score,
    scan_api,
    scan_auth,
    scan_cloud,
    scan_dependencies,
    scan_privacy,
    scan_secrets,
)

app = FastAPI(title="LaunchSafe")

_HERE = Path(__file__).resolve().parent
_FRONTEND = (_HERE.parent / "frontend").resolve()
_STATIC = _HERE / "static"

templates = Jinja2Templates(directory=str(_FRONTEND))
if _STATIC.is_dir():
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

scan_store: dict[str, dict] = {}


# Wire the event-bus that graph nodes use to push live UI events.
EVENT_RING_CAP = 2000     # absolute upper bound; per-scan ring-buffer
EVENT_API_TAIL = 800      # max events returned in a single /scan-status response


def _push_event(scan_id: str, kind: str, text: str, branch: str | None = None, **extra) -> None:
    import time as _time

    scan = scan_store.get(scan_id)
    if scan is None:
        return
    started = scan.get("started_at") or _time.time()
    seq = scan.get("event_seq", 0) + 1
    scan["event_seq"] = seq
    ev = {
        "seq": seq,
        "t": round(_time.time() - started, 1),
        "kind": kind,
        "text": (text or "")[:280],
        "branch": branch or "outer",
    }
    if extra:
        ev.update(extra)
    events = scan.setdefault("events", [])
    events.append(ev)
    if len(events) > EVENT_RING_CAP:
        del events[:len(events) - EVENT_RING_CAP]

    if branch and branch != "outer":
        branch_state = scan.setdefault("branches", {}).setdefault(
            branch, {"status": "pending", "tool_calls": 0, "count": 0}
        )
        if kind == "branch_start":
            branch_state["status"] = "running"
        elif kind == "branch_done":
            branch_state["status"] = "done"
            if "count" in extra:
                branch_state["count"] = extra["count"]
            if "tool_calls" in extra:
                branch_state["tool_calls"] = extra["tool_calls"]
        elif kind == "call":
            branch_state["tool_calls"] = branch_state.get("tool_calls", 0) + 1


set_event_sink(_push_event)



#  AGENT-DRIVEN SCAN


async def run_scan(scan_id: str, files: dict[str, str]) -> None:
    """Drive the LangGraph multi-agent pipeline end-to-end.

    Topology lives in `agents/graph.py`:
        recon -> [general/payments/iac/auth/cicd in parallel] -> synthesize.

    Each node logs branch-tagged events via the shared event-bus
    (`agents.runtime_log`), so the frontend just polls `scan-status` and
    renders whatever it finds.

    Falls back to a pure-regex scan if ANTHROPIC_API_KEY is missing.
    """
    import time

    scan_store[scan_id]["status"] = "running"
    scan_store[scan_id]["started_at"] = time.time()

    _push_event(scan_id, "info", f"Starting scan of {len(files)} files", branch="outer")

    if not os.environ.get("ANTHROPIC_API_KEY"):
        _push_event(scan_id, "warn", "No ANTHROPIC_API_KEY — regex-only fallback", branch="outer")
        await _run_regex_fallback(scan_id, files)
        return

    try:
        from agents.graph import get_agent

        agent = get_agent()
        initial = {
            "messages": [],
            "files": files,
            "scan_id": scan_id,
            "target": scan_store[scan_id]["target"],
            "branch_findings": [],
        }

        final_state: dict | None = None
        async for state in agent.astream(initial, stream_mode="values"):
            if isinstance(state, dict):
                final_state = state
                profile = state.get("repo_profile")
                if profile and not scan_store[scan_id].get("repo_profile"):
                    scan_store[scan_id]["repo_profile"] = profile

        report = (final_state or {}).get("structured_response")
        report_findings: list[dict] = []
        summary = ""
        top_fixes: list[str] = []
        overall_risk = ""

        if report is not None:
            try:
                report_findings = [f.model_dump() for f in getattr(report, "findings", []) or []]
                summary = getattr(report, "summary", "") or ""
                top_fixes = list(getattr(report, "top_fixes", []) or [])
                overall_risk = getattr(report, "overall_risk", "") or ""
            except Exception:  
                pass

        salvaged = [
            f for f in (final_state or {}).get("branch_findings", []) or []
            if isinstance(f, dict) and "_error" not in f
        ]
        if not report_findings and salvaged:
            _push_event(
                scan_id, "warn",
                f"Synthesize produced no report — salvaging {len(salvaged)} branch findings",
                branch="outer",
            )
            report_findings = salvaged

        if not summary and report_findings:
            summary = (
                f"Audit complete. {len(report_findings)} finding(s) across "
                f"{len(scan_store[scan_id].get('branches', {}))} specialist branches."
            )

        score, grade = compute_score(report_findings)
        scan_store[scan_id].update({
            "status": "done",
            "findings": report_findings,
            "score": score,
            "grade": grade,
            "summary": summary,
            "top_fixes": top_fixes,
            "overall_risk": overall_risk or ("high" if grade in ("D", "F") else "medium"),
        })
    except Exception as exc:  
        salvaged = []
        try:
            salvaged = [
                f for f in (final_state or {}).get("branch_findings", []) or []
                if isinstance(f, dict) and "_error" not in f
            ]
        except Exception: 
            pass

        if salvaged:
            _push_event(
                scan_id, "warn",
                f"Pipeline crashed, but salvaged {len(salvaged)} branch findings.",
                branch="outer",
            )
            score, grade = compute_score(salvaged)
            scan_store[scan_id].update({
                "status": "done",
                "findings": salvaged,
                "score": score,
                "grade": grade,
                "summary": (
                    f"Pipeline crashed before synthesize ({str(exc)[:120]}). "
                    f"Showing {len(salvaged)} findings collected during the scan."
                ),
                "top_fixes": [],
                "overall_risk": "high" if grade in ("D", "F") else "medium",
            })
        else:
            scan_store[scan_id].update({
                "status": "error",
                "error": str(exc)[:500],
            })


async def _run_regex_fallback(scan_id: str, files: dict[str, str]) -> None:
    """Pure-deterministic scan used when no Anthropic key is configured."""
    import time as _time

    if not scan_store[scan_id].get("started_at"):
        scan_store[scan_id]["started_at"] = _time.time()
    all_findings: list[dict] = []
    module_fns = [
        ("secrets",  "Secret detection",       scan_secrets),
        ("auth",     "Auth & access review",   scan_auth),
        ("api",      "API security review",    scan_api),
        ("cloud",    "Cloud config audit",     scan_cloud),
        ("privacy",  "Privacy & compliance",   scan_privacy),
        ("deps",     "Dependency scanning",    scan_dependencies),
    ]
    for mod_id, mod_name, fn in module_fns:
        await asyncio.sleep(0.6)
        results = fn(files)
        all_findings.extend(results)
        scan_store[scan_id]["modules_done"].append(
            {"id": mod_id, "name": mod_name, "count": len(results)}
        )
        scan_store[scan_id]["findings"] = list(all_findings)

    score, grade = compute_score(all_findings)
    scan_store[scan_id].update({
        "status": "done",
        "score": score,
        "grade": grade,
        "findings": all_findings,
        "summary": (
            "Regex-only fallback scan (no ANTHROPIC_API_KEY set). "
            f"Found {len(all_findings)} issues across 6 modules."
        ),
        "top_fixes": [],
        "overall_risk": "high" if grade in ("D", "F") else "medium",
    })


#  ROUTES


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_page(request: Request, scan_id: str):
    if scan_id not in scan_store:
        return HTMLResponse("Scan not found", status_code=404)
    return templates.TemplateResponse(request, "scan.html", {"scan_id": scan_id})


@app.get("/report/{scan_id}", response_class=HTMLResponse)
async def report_page(request: Request, scan_id: str):
    scan = scan_store.get(scan_id)
    if not scan or scan["status"] != "done":
        return HTMLResponse("Report not ready", status_code=404)

    findings = scan["findings"]
    counts = {
        "critical": sum(1 for f in findings if f["severity"] == "critical"),
        "high":     sum(1 for f in findings if f["severity"] == "high"),
        "medium":   sum(1 for f in findings if f["severity"] == "medium"),
        "low":      sum(1 for f in findings if f["severity"] == "low"),
    }
    return templates.TemplateResponse(request, "report.html", {
        "scan": scan,
        "findings": findings,
        "counts": counts,
        "total": len(findings),
    })


@app.post("/start-scan")
async def start_scan(
    file: UploadFile = File(None),
    github_url: str = Form(""),
):
    scan_id = str(uuid.uuid4())[:8]
    target = github_url.strip() or (file.filename if file else "uploaded file")
    scan_store[scan_id] = {
        "status": "pending",
        "target": target,
        "findings": [],
        "modules_done": [],
        "events": [],
        "event_seq": 0,
        "branches": {},
        "started_at": None,
        "score": 0,
        "grade": "?",
        "summary": "",
        "top_fixes": [],
        "overall_risk": "",
        "repo_profile": None,
    }

    files: dict[str, str] = {}
    user_provided_input = bool(github_url.strip()) or bool(file and file.filename)

    if github_url.strip():
        try:
            files = await asyncio.to_thread(clone_github, github_url.strip())
        except Exception as exc:  # noqa: BLE001
            scan_store[scan_id].update({
                "status": "error",
                "error": f"Failed to clone {github_url}: {exc!s}",
            })
            return {"scan_id": scan_id}

    elif file and file.filename:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name
        files = extract_zip(tmp_path)
        os.unlink(tmp_path)

    if user_provided_input and not files:
        scan_store[scan_id].update({
            "status": "error",
            "error": (
                "Repo cloned but no scannable files found. Supported extensions "
                "include .py .js .ts .go .rs .c .h .cpp .java .md .yaml .tf and "
                "files like Makefile / Dockerfile / README. Check that the repo "
                "is public and contains source code."
            ),
        })
        return {"scan_id": scan_id}

    if not files:
        files = _demo_files()

    asyncio.create_task(run_scan(scan_id, files))
    return {"scan_id": scan_id}


@app.get("/scan-status/{scan_id}")
async def scan_status(scan_id: str, since: int = 0):
    scan = scan_store.get(scan_id)
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


@app.get("/api/findings/{scan_id}")
async def get_findings(scan_id: str, severity: str = "all"):
    scan = scan_store.get(scan_id)
    if not scan:
        return {"error": "not found"}
    findings = scan.get("findings", [])
    if severity != "all":
        findings = [f for f in findings if f["severity"] == severity]
    return {"findings": findings}


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
    const query = "SELECT * FROM users WHERE email = '" + req.body.email + "'";
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
