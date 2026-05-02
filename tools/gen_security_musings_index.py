#!/usr/bin/env python3
"""Regenerate docs/security-musings/index.md from sibling *.md files (run on build)."""
from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS = REPO_ROOT / "docs"
SECTION = DOCS / "security-musings"
OUT = SECTION / "index.md"


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
keywords_str = _gl.keywords_str
parse_date = _gl.parse_date
git_last_commit_iso = _gl.git_last_commit_iso
ensure_aware = _gl.ensure_aware


def row_sort_time(meta: dict, rel_repo: str, path: Path) -> datetime:
    when = parse_date(meta) or git_last_commit_iso(rel_repo)
    if when is None:
        when = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    return ensure_aware(when)


def format_date_cell(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")


def escape_cell(s: str) -> str:
    return s.replace("|", "\\|")


def collect_rows() -> list[tuple[datetime, str, str, str, str]]:
    rows: list[tuple[datetime, str, str, str, str]] = []
    for path in sorted(SECTION.glob("*.md")):
        if path.name == "index.md":
            continue
        rel_docs = path.relative_to(DOCS).as_posix()
        rel_repo = f"docs/{rel_docs}"
        raw = path.read_text(encoding="utf-8")
        meta, body = parse_front_matter(raw)
        title = (meta.get("title") or first_heading(body)).strip()
        summary = (meta.get("description") or meta.get("summary") or first_paragraph_summary(body)).strip()
        if not summary:
            summary = "—"
        kws = keywords_str(meta)
        when = row_sort_time(meta, rel_repo, path)
        link = path.name
        rows.append((when, title, link, kws, summary))
    rows.sort(key=lambda x: x[0], reverse=True)
    return rows


def main() -> int:
    rows = collect_rows()
    lines = [
        "---",
        'title: "Security musings"',
        "description: Index of notes in this folder (regenerated on each site build).",
        "---",
        "",
        "# Security musings",
        "",
        "Shorter or more opinionated pieces: how security teams interact with delivery, trade-offs, tooling, and "
        "day-to-day engineering—not always tied to a single product or incident. The table below is regenerated "
        "automatically on each site build from the other Markdown notes in this folder.",
        "",
        "| Name | Date | Keywords | Brief summary |",
        "| --- | --- | --- | --- |",
    ]
    for when, title, link, kws, summary in rows:
        lines.append(
            "| [{title}]({link}) | {date} | {kw} | {sum} |".format(
                title=escape_cell(title),
                link=link,
                date=format_date_cell(when),
                kw=escape_cell(kws),
                sum=escape_cell(summary),
            )
        )
    if not rows:
        lines.append("| _No articles yet in this folder._ | — | — | — |")
    lines.extend(
        [
            "",
            "If a thread grows into a long-running series, consider moving it under "
            "[Topics](../topics/genai-ml-security/index.md) or [Incidents & trends](../incidents/index.md) instead.",
            "",
        ]
    )
    new_text = "\n".join(lines) + "\n"
    if OUT.exists() and OUT.read_text(encoding="utf-8") == new_text:
        print(
            f"Unchanged {OUT.relative_to(REPO_ROOT)} ({len(rows)} rows), skip write",
            file=sys.stderr,
        )
        return 0

    OUT.write_text(new_text, encoding="utf-8")
    print(f"Wrote {OUT.relative_to(REPO_ROOT)} ({len(rows)} rows)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
