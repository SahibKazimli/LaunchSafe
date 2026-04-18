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
from pathlib import Path

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

_HERE = Path(__file__).resolve().parent
_FRONTEND = (_HERE.parent / "frontend").resolve()
_STATIC = _HERE / "static"

templates = Jinja2Templates(directory=str(_FRONTEND))
if _STATIC.is_dir():
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

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
    import time

    scan_store[scan_id]["status"] = "running"
    scan_started = time.time()

    def log_event(kind: str, text: str, extra: dict | None = None) -> None:
        ev = {"t": round(time.time() - scan_started, 1), "kind": kind, "text": text[:280]}
        if extra:
            ev.update(extra)
        scan_store[scan_id]["events"].append(ev)
        if len(scan_store[scan_id]["events"]) > 200:
            del scan_store[scan_id]["events"][:50]

    log_event("info", f"Starting scan of {len(files)} files")

    if not os.environ.get("ANTHROPIC_API_KEY"):
        log_event("warn", "No ANTHROPIC_API_KEY — falling back to regex-only scan")
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
        streamed_findings: list[dict] = []
        seen_finding_keys: set[tuple] = set()

        def _ingest_ai_tool_result(raw: str) -> int:
            """Parse findings from an AI tool's JSON response; return count."""
            import json as _json
            try:
                data = _json.loads(raw)
            except Exception:
                return 0
            found = data.get("findings") if isinstance(data, dict) else None
            if not isinstance(found, list):
                return 0
            added = 0
            for f in found:
                if not isinstance(f, dict):
                    continue
                key = (
                    f.get("severity", ""),
                    f.get("title", ""),
                    f.get("location", ""),
                )
                if key in seen_finding_keys:
                    continue
                seen_finding_keys.add(key)
                streamed_findings.append(f)
                added += 1
            return added

        def _tool_args_summary(args: dict) -> str:
            if not args:
                return ""
            parts = []
            for k, v in list(args.items())[:3]:
                s = str(v)
                if len(s) > 60:
                    s = s[:57] + "…"
                parts.append(f"{k}={s}")
            return ", ".join(parts)

        async for namespace, state in agent.astream(
            initial, stream_mode="values", subgraphs=True
        ):
            is_outer = namespace == ()
            if is_outer:
                final_state = state

            if (is_outer and not recon_done and isinstance(state, dict)
                    and state.get("repo_profile")):
                recon_done = True
                scan_store[scan_id]["repo_profile"] = state["repo_profile"]
                scan_store[scan_id]["modules_done"].append(
                    {"id": "recon", "name": "Repo intake", "count": 1}
                )
                stack = state["repo_profile"].get("stack", "")
                log_event("recon", f"Recon complete: {stack}")

            messages = state.get("messages", []) if isinstance(state, dict) else []
            for msg in messages or []:
                msg_type = getattr(msg, "type", None)
                msg_id = getattr(msg, "id", None)
                if msg_id and msg_id in processed_msg_ids:
                    continue
                if msg_id:
                    processed_msg_ids.add(msg_id)

                if msg_type == "ai":
                    content = getattr(msg, "content", "")
                    if isinstance(content, str) and content.strip():
                        log_event("think", content.strip())
                    elif isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "text":
                                txt = block.get("text", "").strip()
                                if txt:
                                    log_event("think", txt)
                    for tc in getattr(msg, "tool_calls", None) or []:
                        tc_name = tc.get("name", "?")
                        tc_args = _tool_args_summary(tc.get("args") or {})
                        log_event("call", f"{tc_name}({tc_args})")

                elif msg_type == "tool":
                    name = getattr(msg, "name", None)
                    content = getattr(msg, "content", "") or ""
                    size = len(content) if isinstance(content, str) else 0

                    added = 0
                    if name in ("ai_scan_file", "ai_scan_cicd", "ai_audit_auth_flow") \
                            and isinstance(content, str):
                        added = _ingest_ai_tool_result(content)
                        scan_store[scan_id]["findings"] = list(streamed_findings)

                    log_event(
                        "result",
                        f"{name} → {size}B" + (f", +{added} findings" if added else ""),
                    )

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
            except Exception:  # noqa: BLE001
                pass

        if not report_findings and streamed_findings:
            log_event(
                "warn",
                f"Final report was incomplete — using {len(streamed_findings)} findings "
                "collected from AI tool calls.",
            )
            report_findings = streamed_findings

        if not summary and streamed_findings:
            summary = (
                f"Audit complete. Collected {len(streamed_findings)} findings from "
                "AI deep-scans. (Executive summary unavailable — final report step "
                "was truncated.)"
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
    except Exception as exc:  # noqa: BLE001
        if streamed_findings:
            log_event(
                "warn",
                f"Agent crashed, but salvaged {len(streamed_findings)} findings from tool calls.",
            )
            score, grade = compute_score(streamed_findings)
            scan_store[scan_id].update({
                "status": "done",
                "findings": streamed_findings,
                "score": score,
                "grade": grade,
                "summary": (
                    f"Audit agent crashed before final report ({str(exc)[:120]}). "
                    f"Showing {len(streamed_findings)} findings collected during the scan."
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
async def scan_status(scan_id: str):
    scan = scan_store.get(scan_id)
    if not scan:
        return {"error": "not found"}
    profile = scan.get("repo_profile")
    if hasattr(profile, "model_dump"):
        profile = profile.model_dump()
    return {
        "status": scan["status"],
        "target": scan.get("target", ""),
        "modules_done": scan.get("modules_done", []),
        "findings_count": len(scan.get("findings", [])),
        "repo_profile": profile,
        "summary": scan.get("summary", ""),
        "overall_risk": scan.get("overall_risk", ""),
        "events": scan.get("events", [])[-40:],
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
