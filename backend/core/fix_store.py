"""In-memory fix session store.
"""

from __future__ import annotations

import time
from typing import Any


_store: dict[str, dict[str, Any]] = {}


def create_fix_session(
    fix_id: str,
    scan_id: str,
    finding_indices: list[int],
) -> dict[str, Any]:
    """Initialise a new fix session and return it."""
    record: dict[str, Any] = {
        "status": "pending",
        "scan_id": scan_id,
        "finding_indices": finding_indices,
        "fix_plan": None,
        "patches": [],
        "review": None,
        "error": None,
        "events": [],
        "event_seq": 0,
        "started_at": None,
        "snapshot_files": None,
        "snapshot_finding_files": None,
        "report_findings_full": [],
        "report_summary": "",
        "report_grade": "",
        "report_top_fixes": [],
        "report_overall_risk": "",
    }
    _store[fix_id] = record
    return record


def get_fix_session(fix_id: str) -> dict[str, Any] | None:
    return _store.get(fix_id)


def update_fix_session(fix_id: str, **fields: Any) -> None:
    session = _store.get(fix_id)
    if session is not None:
        session.update(fields)


def mark_running(fix_id: str) -> None:
    update_fix_session(fix_id, status="running", started_at=time.time())


def exists(fix_id: str) -> bool:
    return fix_id in _store
