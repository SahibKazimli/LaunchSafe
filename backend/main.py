"""LaunchSafe — Startup Security Auditor
FastAPI backend + LangGraph multi-agent pipeline powered by Claude.
Run: uvicorn main:app --reload

This file is PURE BOOTSTRAP / WIRING.  All logic lives in dedicated
modules:
  - core/routes.py       → HTTP endpoints
  - core/orchestrator.py → scan orchestration
  - core/scan_store.py   → in-memory scan state
  - core/events.py       → live event-bus wiring
  - core/config.py       → centralized configuration
  - agents/              → graph, recon, specialists, tools
  - tools/               → scanners, AI tools, ingest
"""

from __future__ import annotations

import os
from pathlib import Path

# Load backend/.env BEFORE importing anything that might read env vars
# (LangChain/Anthropic clients capture ANTHROPIC_API_KEY at import time
# in some versions). `override=True` makes .env win over a stale shell
# variable from a previous session — important when swapping API keys.
try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent / ".env", override=True)
except ImportError:
    pass

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from core.events import setup_event_bus
from core.routes import router

app = FastAPI(title="LaunchSafe")

# Print the first 12 chars of the loaded ANTHROPIC_API_KEY so the
# operator can confirm at a glance which key is in use this session.
# We never print the secret part. If this prefix doesn't match the key
# you put in .env, you have a stale shell var or .env wasn't loaded.
_loaded_key = os.environ.get("ANTHROPIC_API_KEY", "")
if _loaded_key:
    print(f"[LaunchSafe] ANTHROPIC_API_KEY loaded: {_loaded_key[:12]}…")
else:
    print("[LaunchSafe] ANTHROPIC_API_KEY NOT set — will fall back to regex-only scans")

# Wire the event-bus that graph nodes use to push live UI events.
setup_event_bus()

# Mount routes
app.include_router(router)

# Serve static assets if the directory exists
_STATIC = Path(__file__).resolve().parent / "static"
if _STATIC.is_dir():
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")
