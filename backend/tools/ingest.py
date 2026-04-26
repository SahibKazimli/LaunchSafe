"""Repo ingestion: zip archives and GitHub URLs both produce dict[path, content]."""

from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path

from core.config import MAX_INGEST_FILE_BYTES
from .scanners import SKIP_DIRS, is_scannable


def _walk_repo(root: str) -> dict[str, str]:
    """Walk a directory and return {relpath: text_content} for scannable files."""
    out: dict[str, str] = {}
    root_path = Path(root)
    for file_path in root_path.rglob("*"):
        if not file_path.is_file():
            continue
        if any(part in SKIP_DIRS for part in file_path.parts):
            continue
        if not is_scannable(file_path.name):
            continue
        try:
            if file_path.stat().st_size > MAX_INGEST_FILE_BYTES:
                continue
            rel = str(file_path.relative_to(root_path))
            out[rel] = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass
    return out


def extract_zip(zip_path: str) -> dict[str, str]:
    """Extract text files from a zip archive."""
    files: dict[str, str] = {}
    try:
        with zipfile.ZipFile(zip_path) as zip_archive:
            for info in zip_archive.infolist():
                if info.is_dir():
                    continue
                entry_path = Path(info.filename)
                if any(part in SKIP_DIRS for part in entry_path.parts):
                    continue
                if not is_scannable(entry_path.name):
                    continue
                if info.file_size > MAX_INGEST_FILE_BYTES:
                    continue
                try:
                    files[info.filename] = zip_archive.read(info.filename).decode(
                        "utf-8", errors="replace"
                    )
                except Exception:
                    pass
    except Exception:
        pass
    return files


def clone_github(url: str) -> dict[str, str]:
    """Shallow-clone a public GitHub repo and return its scannable files."""
    try:
        from git import Repo
    except ImportError as e:
        raise RuntimeError(
            "gitpython is not installed. Run: pip install gitpython"
        ) from e

    with tempfile.TemporaryDirectory() as clone_dir:
        Repo.clone_from(url, clone_dir, depth=1)
        return _walk_repo(clone_dir)
