# LaunchSafe — Startup Security Auditor

LaunchSafe is an AI-driven security auditor for early-stage codebases.
Point it at a public GitHub repo (or upload a ZIP) and it returns a
prioritized, CVSS-scored security report in a few minutes.

It is built on a small but real **multi-agent LangGraph pipeline** powered
by Claude — not just regex scanning. A reconnaissance agent profiles the
repo, then specialist sub-agents run in parallel against the parts of the
codebase that actually matter (auth, payments, IaC, CI/CD, plus a general
sweep). Findings are merged, deduped, and graded.



URL: https://launchsafe-851230900226.europe-north2.run.app
---

## What it actually checks

| Specialist            | Focus                                                                 |
|-----------------------|-----------------------------------------------------------------------|
| `recon`               | Profiles the repo: language, framework, payments / IaC / auth flags   |
| `payments`            | Stripe / PCI exposure, webhook signature verification, key handling   |
| `iac`                 | Terraform / K8s / Docker — public buckets, exposed DBs, IAM wildcards |
| `auth`                | Login, session, JWT, password hashing, RBAC / IDOR                    |
| `cicd`                | GitHub Actions / GitLab CI — secrets, untrusted PR triggers, OIDC     |
| `general`             | Secrets, crypto, SQLi, SSRF, deserialization, CORS, dependency CVEs   |
| `synthesize`          | Dedupes across branches, writes the executive summary                 |

Each finding gets a CVSS v3.1-aligned base score and a deployment-context
**exposure** tag (`production` / `internal` / `test` / `example` / `doc`)
so test-fixture code doesn't drag a library repo's grade down to F.

---

## Architecture

```
                  ┌──────────────────────────────────────────┐
                  │            FastAPI (main.py)             │
                  │  /start-scan  /scan-status  /report/<id> │
                  └──────────────────────┬───────────────────┘
                                         │
                                         ▼
                              LangGraph orchestrator
                                         │
                                  ┌──────┴──────┐
                                  │    recon    │  ◄── mini ReAct agent
                                  │ (mini agent)│      (list_files, read_files)
                                  └──────┬──────┘
                                         │  RepoProfile + flags
                                         ▼
                          route_after_recon (conditional fan-out)
                       │       │       │       │       │
                       ▼       ▼       ▼       ▼       ▼
                  payments   iac    auth    cicd   general    ◄── parallel
                  ReAct      ReAct  ReAct   ReAct  ReAct           sub-agents
                       │       │       │       │       │       (each w/ AI tools)
                       └───────┴───┬───┴───────┴───────┘
                                   ▼
                              synthesize  ◄── dedupe + LLM exec summary
                                   │
                                   ▼
                              Report JSON
```

All sub-agents stream their `think → call → result` events live to the
frontend over, so the user sees what each branch is doing as it happens.

---

## Quick start (local)

```bash
git clone https://github.com/SahibKazimli/LaunchSafe.git
cd LaunchSafe

# 1. Python env
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt

# 2. Anthropic key (required for the AI agents — falls back to regex-only without it)
cp backend/.env.example backend/.env
# then edit backend/.env and paste your ANTHROPIC_API_KEY

# 3. Run
cd backend
uvicorn main:app --reload

# 4. Open
open http://127.0.0.1:8000
```

The boot log prints the first 12 chars of the loaded API key so you can
confirm which one is being used:

```
[LaunchSafe] ANTHROPIC_API_KEY loaded: sk-ant-api03…
```

---

## Repo layout

```
LaunchSafe/
├── README.md
├── Dockerfile                    
├── .dockerignore
├── backend/
│   ├── main.py                   # FastAPI app, scan orchestration, event stream
│   ├── requirements.txt
│   ├── .env.example
│   └── agents/
│       ├── graph.py              # LangGraph StateGraph wiring
│       ├── state.py              # ScanAgentState (shared agent state)
│       ├── recon.py              # Recon mini-agent
│       ├── specialists.py        # payments / iac / auth / cicd / general
│       ├── synthesize.py         # Dedupe + executive summary LLM call
│       ├── runtime_log.py        # Event bus for live UI streaming
│       ├── schemas.py            # Pydantic models + LLM rubrics
│       └── tools/
│           ├── ingest.py         # GitHub clone + zip extraction
│           ├── scanners.py       # Regex scanners + CVSS scoring engine
│           ├── ai_tools.py       # ai_scan_file / ai_scan_cicd / ai_audit_auth_flow
│           └── agent_tools.py    # list_files / read_file / read_files
└── frontend/
    ├── base.html                 # Shared layout
    ├── index.html                # Upload page
    ├── scan.html                 # Live scan progress (branches + event log)
    └── report.html               # Final findings report
```

---

## Risk scoring (the short version)

```
contribution = cvss_base × exposure_multiplier        # per finding
risk_total   = Σ contribution (only is_true_positive=True findings)
score        = clamp(100 − 2 × risk_total, 0, 100)
```

Exposure multipliers: `production 1.00`, `internal 0.60`, `test 0.15`,
`example 0.05`, `doc 0.03`.

Grade is bucketed on `risk_total` (lower = better):

| risk_total | grade |
|---|---|
| ≤ 5    | A |
| ≤ 12.5 | B |
| ≤ 20   | C |
| ≤ 30   | D |
| > 30   | F |

The full per-finding math (CVSS, exposure, contribution) is shown on
the report sidebar.

---

## Tech stack

- **FastAPI** + **Jinja2** — web layer
- **LangGraph** — agent orchestration (conditional fan-out, parallel branches, state reducers)
- **LangChain** + **Anthropic Claude** — sub-agent reasoning and structured output
- **Pydantic** — typed schemas for `Finding` / `AuditReport` / `ComplianceRef`
- **GitPython** — repo cloning
- **python-dotenv** — `.env` loading


