#!/usr/bin/env python3
"""Shared helpers for Essays + home browse generators."""
from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS = REPO_ROOT / "docs"
ESSAYS_DIR = DOCS / "essays"
CONFIG_PATH = Path(__file__).resolve().parent / "home_browse.yml"


def _load_gen_latest_writing():
    path = REPO_ROOT / "tools" / "gen_latest_writing.py"
    spec = importlib.util.spec_from_file_location("_gen_latest_writing", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_gl = _load_gen_latest_writing()
parse_front_matter = _gl.parse_front_matter
first_heading = _gl.first_heading
first_paragraph_summary = _gl.first_paragraph_summary
parse_date = _gl.parse_date
git_last_commit_iso = _gl.git_last_commit_iso
ensure_aware = _gl.ensure_aware


@dataclass
class Essay:
    filename: str
    title: str
    category: str
    summary: str
    when: datetime
    # link relative to essays folder
    link: str


def load_config() -> dict:
    return yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}


def one_liner(text: str, limit: int = 160) -> str:
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    cut = text[: limit - 1].rsplit(" ", 1)[0]
    return cut + "…"


def essay_sort_time(meta: dict, rel_repo: str, path: Path) -> datetime:
    when = parse_date(meta) or git_last_commit_iso(rel_repo)
    if when is None:
        when = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    return ensure_aware(when)


def collect_essays(cfg: dict | None = None) -> list[Essay]:
    cfg = cfg or load_config()
    cat_map: dict[str, str] = cfg.get("essay_categories") or {}
    sum_map: dict[str, str] = cfg.get("essay_summaries") or {}
    order: list[str] = cfg.get("essay_category_order") or []
    order_index = {name: i for i, name in enumerate(order)}

    essays: list[Essay] = []
    for path in sorted(ESSAYS_DIR.glob("*.md")):
        if path.name == "index.md":
            continue
        rel_repo = f"docs/{path.relative_to(DOCS).as_posix()}"
        raw = path.read_text(encoding="utf-8")
        meta, body = parse_front_matter(raw)
        title = (meta.get("title") or first_heading(body)).strip()
        category = (meta.get("category") or cat_map.get(path.name) or "Uncategorized").strip()
        summary = (
            sum_map.get(path.name)
            or meta.get("summary")
            or meta.get("description")
            or first_paragraph_summary(body, limit=160)
        )
        summary = one_liner(str(summary).strip() or "—")
        when = essay_sort_time(meta, rel_repo, path)
        essays.append(
            Essay(
                filename=path.name,
                title=title,
                category=category,
                summary=summary,
                when=when,
                link=path.name,
            )
        )

    def sort_key(e: Essay):
        return (order_index.get(e.category, 999), -e.when.timestamp(), e.title.lower())

    essays.sort(key=sort_key)
    return essays


def group_essays(essays: list[Essay], cfg: dict | None = None) -> list[tuple[str, list[Essay]]]:
    cfg = cfg or load_config()
    order: list[str] = list(cfg.get("essay_category_order") or [])
    buckets: dict[str, list[Essay]] = {c: [] for c in order}
    extra: dict[str, list[Essay]] = {}
    for e in essays:
        if e.category in buckets:
            buckets[e.category].append(e)
        else:
            extra.setdefault(e.category, []).append(e)
    grouped = [(c, buckets[c]) for c in order if buckets[c]]
    for c, items in sorted(extra.items()):
        grouped.append((c, items))
    return grouped


def build_essays_nav(cfg: dict | None = None) -> list:
    """MkDocs nav children for Essays: section index, then category → essays."""
    cfg = cfg or load_config()
    # First entry is the section index (works with theme feature navigation.indexes).
    children: list = ["essays/index.md"]
    for category, items in group_essays(collect_essays(cfg), cfg):
        children.append(
            {category: [{e.title: f"essays/{e.filename}"} for e in items]}
        )
    return children


def write_if_changed(path: Path, text: str, label: str) -> bool:
    if path.exists() and path.read_text(encoding="utf-8") == text:
        print(f"Unchanged {path.relative_to(REPO_ROOT)} ({label}), skip write", file=sys.stderr)
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    print(f"Wrote {path.relative_to(REPO_ROOT)} ({label})", file=sys.stderr)
    return True
