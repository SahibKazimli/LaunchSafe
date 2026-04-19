"""Lightweight event-bus used by graph nodes to push live UI events.

`main.py` registers a sink at startup that writes into `scan_store`.
Graph nodes call `emit(scan_id, kind, text, branch=...)` — if no sink
is registered (e.g. during unit tests) the calls are no-ops.

Decoupled in its own module to avoid `agents/* -> main` import cycles.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

EventSink = Callable[..., None]

_sink: Optional[EventSink] = None


def set_event_sink(fn: EventSink) -> None:
    global _sink
    _sink = fn


def emit(
    scan_id: str | None,
    kind: str,
    text: str,
    branch: str | None = None,
    **extra: Any,
) -> None:
    if _sink is None or not scan_id:
        return
    try:
        _sink(scan_id=scan_id, kind=kind, text=text, branch=branch, **extra)
    except Exception:  # noqa: BLE001
        pass
