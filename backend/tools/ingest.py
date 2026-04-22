"""Repo ingestion: zip archives and GitHub URLs both produce dict[path, content]."""

from __future__ import annotations

from pathlib import Path

from core.config import MAX_INGEST_FILE_BYTES
from .scanners import SKIP_DIRS, is_scannable
import tempfile

def _walk_repo(root: str) -> dict[str, str]:
    """Walk a directory and return {relpath: text_content} for scannable files."""
    out: dict[str, str] = {}
    root_path = Path(root)
    for p in root_path.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if not is_scannable(p.name):
            continue
        try:
            if p.stat().st_size > MAX_INGEST_FILE_BYTES:
                continue
            rel = str(p.relative_to(root_path))
            out[rel] = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass
    return out



def clone_github(url: str) -> dict[str, str]:
    try:
        from git import Repo
    except ImportError as e:
        raise RuntimeError("gitpython is not installed. Run: pip install gitpython") from e

    with tempfile.TemporaryDirectory() as d:
        Repo.clone_from(url, d, depth=1)
        return _walk_repo(d)
