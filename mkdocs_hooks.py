"""MkDocs hooks: regenerate derived Markdown before each build (serve live-reload and mkdocs build).

Runs index generators so `mkdocs serve` stays in sync. Generators skip writing when output is
unchanged so includes do not retrigger live reload in a tight loop.

Also refreshes minibook PDFs when chapter sources change, and loads topic edition
metadata (version / date) into config.extra for the chapter chrome.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml


def _inject_essays_nav(config) -> None:
    """Replace Essays children with category → essay nesting."""
    root = Path(config["config_file_path"]).resolve().parent
    sys.path.insert(0, str(root / "tools"))
    from essay_catalog import build_essays_nav  # noqa: E402

    essays_children = build_essays_nav()
    nav = config.get("nav") or []
    for i, item in enumerate(nav):
        if isinstance(item, dict) and "Essays" in item:
            nav[i] = {"Essays": essays_children}
            config["nav"] = nav
            return


def on_config(config):
    root = Path(config["config_file_path"]).resolve().parent
    books_path = root / "tools" / "minibooks.yml"
    books = {}
    if books_path.exists():
        data = yaml.safe_load(books_path.read_text(encoding="utf-8")) or {}
        books = data.get("books") or {}
    extra = config.get("extra") or {}
    extra["minibooks"] = books
    config["extra"] = extra
    _inject_essays_nav(config)
    return config


def on_pre_build(config):
    root = Path(config["config_file_path"]).resolve().parent
    r = subprocess.run(
        [sys.executable, str(root / "tools" / "regen_indexes.py")],
        cwd=root,
        check=False,
    )
    if r.returncode != 0:
        raise RuntimeError(f"regen_indexes failed ({r.returncode})")

    pdf = subprocess.run(
        [sys.executable, str(root / "tools" / "gen_minibooks.py")],
        cwd=root,
        check=False,
    )
    if pdf.returncode != 0:
        raise RuntimeError(f"gen_minibooks failed ({pdf.returncode})")
