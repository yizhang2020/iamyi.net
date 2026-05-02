#!/usr/bin/env python3
"""Build docs/includes/latest-writing.md for the home page (10 most recently updated docs)."""
from __future__ import annotations

import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS = REPO_ROOT / "docs"
OUT = DOCS / "includes" / "latest-writing.md"
MAX_ROWS = 10

SKIP_REL = frozenset(
    {
        "incidents/_template-incident-note.md",
    }
)


def git_last_commit_iso(rel: str) -> datetime | None:
    """Return commit time of last change to rel (path under repo root), or None."""
    try:
        out = subprocess.run(
            ["git", "log", "-1", "--format=%cI", "--", rel],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if out.returncode != 0 or not out.stdout.strip():
            return None
        raw = out.stdout.strip()
        return ensure_aware(datetime.fromisoformat(raw.replace("Z", "+00:00")))
    except (ValueError, OSError):
        return None


def parse_front_matter(raw: str) -> tuple[dict, str]:
    if not raw.lstrip().startswith("---") or yaml is None:
        return {}, raw
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n?", raw, re.DOTALL)
    if not m:
        return {}, raw
    try:
        meta = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError:
        meta = {}
    rest = raw[m.end() :]
    return meta, rest


def first_heading(body: str) -> str:
    for line in body.splitlines():
        m = re.match(r"^#{1,6}\s+(.*)", line.strip())
        if m:
            return m.group(1).strip()
    return "Untitled"


def first_paragraph_summary(body: str, limit: int = 140) -> str:
    text = body
    text = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"[*_`#>|]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        return text[: limit - 1].rsplit(" ", 1)[0] + "…"
    return text


def keywords_str(meta: dict) -> str:
    kw = meta.get("keywords") or meta.get("tags")
    if isinstance(kw, list):
        return ", ".join(str(x) for x in kw)
    if isinstance(kw, str):
        return kw
    return "—"


def ensure_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def parse_date(meta: dict) -> datetime | None:
    for key in ("updated", "date", "revision_date"):
        val = meta.get(key)
        if not val:
            continue
        if isinstance(val, datetime):
            return ensure_aware(val)
        s = str(val).strip()
        try:
            return ensure_aware(datetime.fromisoformat(s.replace("Z", "+00:00")))
        except ValueError:
            pass
    return None


def _strip_include_preamble(text: str) -> str:
    """Strip optional first line (Updated at / Last update) and following blank line for comparisons."""
    lines = text.splitlines()
    i = 0
    if lines and (
        lines[0].startswith("Updated at ")
        or lines[0].startswith("Last update time:")
    ):
        i = 1
        if i < len(lines) and lines[i].strip() == "":
            i += 1
    return "\n".join(lines[i:])


def format_updated_at() -> str:
    """Compact local time for the include preamble, e.g. Updated at May 2, 2026, 9:31 AM."""
    now = datetime.now().astimezone()
    h = now.hour
    h12 = h % 12
    if h12 == 0:
        h12 = 12
    ampm = "AM" if h < 12 else "PM"
    month = now.strftime("%B")
    return f"Updated at {month} {now.day}, {now.year}, {h12}:{now.minute:02d} {ampm}"


def collect() -> list[tuple[datetime, str, str, str, str, Path]]:
    rows: list[tuple[datetime, str, str, str, str, Path]] = []
    for path in sorted(DOCS.rglob("*.md")):
        rel_docs = path.relative_to(DOCS).as_posix()
        if rel_docs == "index.md":
            continue  # home page
        if path.name == "index.md":
            continue  # section hub pages (topics/, security-musings/, incidents/)
        if rel_docs.startswith("includes/"):
            continue  # generated snippets, not articles
        if rel_docs in SKIP_REL:
            continue
        raw = path.read_text(encoding="utf-8")
        meta, body = parse_front_matter(raw)
        title = (meta.get("title") or first_heading(body)).strip()
        summary = (meta.get("description") or meta.get("summary") or first_paragraph_summary(body)).strip()
        if not summary:
            summary = "—"
        kws = keywords_str(meta)
        rel_repo = f"docs/{rel_docs}"
        when = parse_date(meta) or git_last_commit_iso(rel_repo)
        if when is None:
            when = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        else:
            when = ensure_aware(when)
        link = rel_docs
        rows.append((when, title, link, kws, summary, path))

    # Most recently updated first (when = front matter dates, else git, else mtime).
    rows.sort(key=lambda x: x[0], reverse=True)
    return rows[:MAX_ROWS]


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    rows = collect()
    lines = [
        format_updated_at(),
        "",
        "| Writing | Keywords | Summary |",
        "| --- | --- | --- |",
    ]
    for _when, title, link, kws, summary, _path in rows:
        safe_title = title.replace("|", "\\|")
        safe_sum = summary.replace("|", "\\|")
        safe_kw = kws.replace("|", "\\|")
        lines.append(
            f"| [{safe_title}]({link}) | {safe_kw} | {safe_sum} |"
        )
    if not rows:
        lines.append("| _No articles yet._ | — | — |")

    new_text = "\n".join(lines) + "\n"
    if OUT.exists():
        old_raw = OUT.read_text(encoding="utf-8")
        old_norm = _strip_include_preamble(old_raw).rstrip("\n")
        new_norm = _strip_include_preamble(new_text).rstrip("\n")
        if old_norm == new_norm:
            if old_raw == new_text:
                print(
                    f"Unchanged {OUT.relative_to(REPO_ROOT)} ({len(rows)} rows; skip write)",
                    file=sys.stderr,
                )
                return 0
            OUT.write_text(new_text)
            print(
                f"Normalized {OUT.relative_to(REPO_ROOT)} ({len(rows)} rows; refreshed preamble)",
                file=sys.stderr,
            )
            return 0

    OUT.write_text(new_text, encoding="utf-8")
    print(f"Wrote {OUT.relative_to(REPO_ROOT)} ({len(rows)} rows)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
