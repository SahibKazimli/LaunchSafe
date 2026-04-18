"""
LaunchSafe / AuditShield — Startup Security Auditor
FastAPI backend + single LangGraph ReAct agent powered by Claude.
Run: uvicorn main:app --reload
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import uuid

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from agents.tools.agent_tools import SCANNER_TOOL_TO_MODULE
from agents.tools.ai_tools import AI_TOOL_TO_MODULE
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

TOOL_TO_MODULE = {**SCANNER_TOOL_TO_MODULE, **AI_TOOL_TO_MODULE}

app = FastAPI(title="LaunchSafe")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

scan_store: dict[str, dict] = {}


# ════════════════════════════════════════════════════════════════════════════
#  AGENT-DRIVEN SCAN
# ════════════════════════════════════════════════════════════════════════════

async def run_scan(scan_id: str, files: dict[str, str]) -> None:
    """Drive the LangGraph ReAct agent end-to-end and populate scan_store.

    Streams state updates so the frontend's polling endpoint can show
    per-module progress in real time. Falls back to a pure-regex scan when
    no ANTHROPIC_API_KEY is configured, so the demo path always works.
    """
    scan_store[scan_id]["status"] = "running"

    if not files:
        files = _demo_files()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        await _run_regex_fallback(scan_id, files)
        return

    try:
        from agents.graph import get_agent

        agent = get_agent()
        initial = {
            "messages": [{
                "role": "user",
                "content": (
                    f"Audit the uploaded codebase ({len(files)} files). "
                    "Use your tools to run the relevant scanners, inspect any "
                    "suspicious findings with read_file if needed, then return "
                    "a prioritised AuditReport."
                ),
            }],
            "files": files,
            "scan_id": scan_id,
            "target": scan_store[scan_id]["target"],
        }

        final_state = None
        recon_done = False
        processed_msg_ids: set[str] = set()
        tool_row_index: dict[str, int] = {}

        async for state in agent.astream(initial, stream_mode="values"):
            final_state = state

            if not recon_done and state.get("repo_profile"):
                recon_done = True
                scan_store[scan_id]["repo_profile"] = state["repo_profile"]
                scan_store[scan_id]["modules_done"].append(
                    {"id": "recon", "name": "Repo intake", "count": 1}
                )

            for msg in state.get("messages", []) or []:
                if getattr(msg, "type", None) != "tool":
                    continue
                msg_id = getattr(msg, "id", None)
                if msg_id and msg_id in processed_msg_ids:
                    continue
                if msg_id:
                    processed_msg_ids.add(msg_id)

                name = getattr(msg, "name", None)
                if name not in TOOL_TO_MODULE:
                    continue

                mod_id, mod_name = TOOL_TO_MODULE[name]
                rows = scan_store[scan_id]["modules_done"]
                if name in tool_row_index:
                    rows[tool_row_index[name]]["count"] += 1
                else:
                    tool_row_index[name] = len(rows)
                    rows.append({"id": mod_id, "name": mod_name, "count": 1})

        report = (final_state or {}).get("structured_response")

        if report is None:
            scan_store[scan_id].update({
                "status": "error",
                "error": "Agent did not return a structured AuditReport.",
            })
            return

        findings = [f.model_dump() for f in report.findings]

        score, grade = compute_score(findings)
        scan_store[scan_id].update({
            "status": "done",
            "findings": findings,
            "score": score,
            "grade": grade,
            "summary": report.summary,
            "top_fixes": report.top_fixes,
            "overall_risk": report.overall_risk,
        })
    except Exception as exc:  # noqa: BLE001
        scan_store[scan_id].update({
            "status": "error",
            "error": str(exc)[:500],
        })


async def _run_regex_fallback(scan_id: str, files: dict[str, str]) -> None:
    """Pure-deterministic scan used when no Anthropic key is configured."""
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


# ════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_page(request: Request, scan_id: str):
    if scan_id not in scan_store:
        return HTMLResponse("Scan not found", status_code=404)
    return templates.TemplateResponse("scan.html", {"request": request, "scan_id": scan_id})


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
    return templates.TemplateResponse("report.html", {
        "request": request,
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
        "score": 0,
        "grade": "?",
        "summary": "",
        "top_fixes": [],
        "overall_risk": "",
        "repo_profile": None,
    }

    files: dict[str, str] = {}

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

    if not files:
        files = _demo_files()

    asyncio.create_task(run_scan(scan_id, files))
    return {"scan_id": scan_id}


@app.get("/scan-status/{scan_id}")
async def scan_status(scan_id: str):
    scan = scan_store.get(scan_id)
    if not scan:
        return {"error": "not found"}
    return {
        "status": scan["status"],
        "modules_done": scan.get("modules_done", []),
        "findings_count": len(scan.get("findings", [])),
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
