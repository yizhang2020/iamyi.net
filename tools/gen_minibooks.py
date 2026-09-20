#!/usr/bin/env python3
"""Generate printable minibook PDFs for each docs/minibooks/* book.

Each PDF includes a cover, copyright page, table of contents, and chapters
in mkdocs.yml nav order. Output: docs/minibooks/<slug>/minibook/<pdf_filename>.

Regenerates only when sources are newer than the PDF (or the PDF is missing).
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from datetime import date
from pathlib import Path

import markdown
import yaml

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
MKDOCS_YML = ROOT / "mkdocs.yml"
BOOKS_YML = Path(__file__).resolve().parent / "minibooks.yml"

FRONT_MATTER_RE = re.compile(r"^---\s*\n.*?\n---\s*\n", re.DOTALL)
MD = markdown.Markdown(
    extensions=[
        "markdown.extensions.tables",
        "markdown.extensions.fenced_code",
        "markdown.extensions.nl2br",
        "markdown.extensions.sane_lists",
        "markdown.extensions.toc",
    ]
)


def load_yaml(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    # mkdocs.yml may contain tabs; PyYAML accepts them.
    return yaml.safe_load(text)


def flatten_nav_paths(node, out: list[str]) -> None:
    if isinstance(node, str):
        if node.endswith(".md"):
            out.append(node.replace("\\", "/"))
        return
    if isinstance(node, dict):
        for value in node.values():
            flatten_nav_paths(value, out)
        return
    if isinstance(node, list):
        for item in node:
            flatten_nav_paths(item, out)


def chapter_paths_for_topic(nav: list, topic: str) -> list[str]:
    prefix = f"minibooks/{topic}/"
    paths: list[str] = []
    flatten_nav_paths(nav, paths)
    chapters = [p for p in paths if p.startswith(prefix) and not p.endswith("/index.md")]
    # Deduplicate while preserving order
    seen: set[str] = set()
    ordered: list[str] = []
    for p in chapters:
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    return ordered


def strip_front_matter(text: str) -> str:
    return FRONT_MATTER_RE.sub("", text, count=1)


def chapter_title(md_text: str, fallback: str) -> str:
    # Prefer first ATX heading after front matter
    for line in md_text.splitlines():
        m = re.match(r"^#{1,3}\s+(.+?)\s*$", line)
        if m:
            return m.group(1).strip()
    return fallback


def md_to_html(md_text: str) -> str:
    MD.reset()
    return MD.convert(md_text)


def newest_mtime(paths: list[Path]) -> float:
    return max((p.stat().st_mtime for p in paths if p.exists()), default=0.0)


def needs_rebuild(pdf: Path, sources: list[Path]) -> bool:
    if not pdf.exists():
        return True
    return newest_mtime(sources) > pdf.stat().st_mtime


BOOK_CSS = """
@page {
  size: letter;
  margin: 22mm 18mm 24mm 18mm;
  @bottom-center {
    content: counter(page);
    font-family: "Source Sans 3", "Helvetica Neue", Helvetica, Arial, sans-serif;
    font-size: 9pt;
    color: #5a6a6a;
  }
}
@page cover {
  margin: 0;
  @bottom-center { content: none; }
}
@page copyright {
  @bottom-center { content: none; }
}

html { font-size: 10.5pt; }
body {
  font-family: "Source Serif 4", "Georgia", "Times New Roman", serif;
  color: #1a2424;
  line-height: 1.45;
}

.cover {
  page: cover;
  min-height: 100vh;
  padding: 48mm 22mm 28mm;
  box-sizing: border-box;
  background:
    linear-gradient(165deg, #0d3d3d 0%, #146666 42%, #1a7a6e 70%, #c9a227 160%);
  color: #f4f7f6;
  position: relative;
  overflow: hidden;
}
.cover-brand {
  font-family: "Source Sans 3", "Helvetica Neue", Helvetica, Arial, sans-serif;
  font-size: 11pt;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  opacity: 0.85;
  margin: 0 0 28mm;
}
.cover h1 {
  font-family: "Source Sans 3", "Helvetica Neue", Helvetica, Arial, sans-serif;
  font-weight: 700;
  font-size: 34pt;
  line-height: 1.15;
  margin: 0 0 8mm;
  max-width: 28ch;
}
.cover .subtitle {
  font-size: 13pt;
  line-height: 1.4;
  max-width: 42ch;
  opacity: 0.92;
  margin: 0 0 36mm;
}
.cover .meta {
  font-family: "Source Sans 3", "Helvetica Neue", Helvetica, Arial, sans-serif;
  font-size: 11pt;
  opacity: 0.9;
}
.cover .meta p { margin: 0 0 2mm; }
.cover-inner {
  position: relative;
  z-index: 1;
}

/* Trace lattice — influence-first abstract cover */
.cover.cover-trace-lattice {
  background:
    linear-gradient(165deg, #0d3d3d 0%, #146666 42%, #1a7a6e 72%, #0f4a48 100%);
  color: #f4f7f6;
  padding: 42mm 22mm 26mm;
}
.cover.cover-trace-lattice .cover-art {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  z-index: 0;
}
.cover.cover-trace-lattice .cover-inner {
  position: relative;
  z-index: 1;
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  box-sizing: border-box;
  padding: 0;
}
.cover.cover-trace-lattice .cover-brand {
  opacity: 0.8;
  letter-spacing: 0.18em;
  margin: 0 0 52mm;
}
.cover.cover-trace-lattice h1 {
  font-weight: 600;
  font-size: 32pt;
  letter-spacing: -0.01em;
  max-width: 16ch;
  margin: 0 0 10mm;
}
.cover.cover-trace-lattice .subtitle {
  font-family: "Source Serif 4", "Georgia", "Times New Roman", serif;
  font-size: 14pt;
  font-style: italic;
  opacity: 0.9;
  max-width: 28ch;
  margin: 0 0 auto;
}
.cover.cover-trace-lattice .meta {
  margin-top: 40mm;
  opacity: 0.88;
  font-size: 10pt;
}
.cover.cover-trace-lattice .meta p { margin: 0 0 1.5mm; }

.copyright {
  page: copyright;
  padding-top: 28mm;
}
.copyright h1 {
  font-family: "Source Sans 3", "Helvetica Neue", Helvetica, Arial, sans-serif;
  font-size: 16pt;
  margin: 0 0 8mm;
}
.copyright p {
  font-family: "Source Sans 3", "Helvetica Neue", Helvetica, Arial, sans-serif;
  font-size: 10.5pt;
  max-width: 58ch;
  margin: 0 0 4mm;
}
.copyright a { color: #146666; text-decoration: none; }

.toc { page: toc; }
.toc h1 {
  font-family: "Source Sans 3", "Helvetica Neue", Helvetica, Arial, sans-serif;
  font-size: 18pt;
  margin: 0 0 10mm;
}
.toc ul {
  list-style: none;
  padding: 0;
  margin: 0;
}
.toc li {
  font-family: "Source Sans 3", "Helvetica Neue", Helvetica, Arial, sans-serif;
  font-size: 10pt;
  margin: 0 0 2.2mm;
  page-break-inside: avoid;
}
.toc a {
  color: #1a2424;
  text-decoration: none;
}
.toc a::after {
  content: leader(".") target-counter(attr(href), page);
  font-variant-numeric: tabular-nums;
}

.chapter {
  page-break-before: always;
}
.chapter > h1:first-child,
.chapter > h2:first-child {
  font-family: "Source Sans 3", "Helvetica Neue", Helvetica, Arial, sans-serif;
  font-size: 18pt;
  line-height: 1.25;
  margin: 0 0 6mm;
  color: #0d3d3d;
}
.chapter h2, .chapter h3, .chapter h4 {
  font-family: "Source Sans 3", "Helvetica Neue", Helvetica, Arial, sans-serif;
  color: #0d3d3d;
  page-break-after: avoid;
}
.chapter h2 { font-size: 13.5pt; margin: 7mm 0 3mm; }
.chapter h3 { font-size: 11.5pt; margin: 5mm 0 2mm; }
.chapter p, .chapter li { orphans: 3; widows: 3; }
.chapter a { color: #146666; }

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 9pt;
  margin: 4mm 0 6mm;
  page-break-inside: avoid;
}
th, td {
  border: 0.4pt solid #b7c4c4;
  padding: 2mm 2.5mm;
  text-align: left;
  vertical-align: top;
}
th {
  background: #e8f2f1;
  font-family: "Source Sans 3", "Helvetica Neue", Helvetica, Arial, sans-serif;
}

pre, code {
  font-family: "Source Code Pro", "Menlo", "Consolas", monospace;
  font-size: 8.2pt;
}
pre {
  background: #f3f6f6;
  border: 0.4pt solid #d5e0e0;
  padding: 3mm;
  white-space: pre-wrap;
  word-break: break-word;
  page-break-inside: avoid;
  margin: 3mm 0 5mm;
}
blockquote {
  margin: 3mm 0 5mm;
  padding: 0 0 0 4mm;
  border-left: 2.5pt solid #c9a227;
  color: #334040;
}

strong { font-weight: 700; }
"""


TRACE_LATTICE_SVG = """
<svg class="cover-art" viewBox="0 0 612 792" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <!-- Sparse influence graph; one cluster bounded (authority). Units ≈ letter points. -->
  <g fill="none" stroke-linecap="round" stroke-linejoin="round">
    <!-- Outer faint traces -->
    <g stroke="#a8d4cf" stroke-width="0.6" opacity="0.28">
      <path d="M72 120 L148 210 L118 320"/>
      <path d="M148 210 L240 168 L310 240"/>
      <path d="M520 96 L460 180 L510 260"/>
      <path d="M560 340 L490 400 L540 480"/>
      <path d="M80 520 L150 560 L120 640"/>
      <path d="M200 700 L280 650 L360 720"/>
      <path d="M40 400 L90 450"/>
      <path d="M580 600 L500 640 L560 700"/>
    </g>
    <!-- Mid connections into the bound cluster -->
    <g stroke="#d0ebe7" stroke-width="0.75" opacity="0.38">
      <path d="M240 168 L320 300"/>
      <path d="M118 320 L280 360"/>
      <path d="M460 180 L400 310"/>
      <path d="M490 400 L410 380"/>
      <path d="M150 560 L300 480"/>
      <path d="M280 650 L350 520"/>
    </g>
    <!-- Bound cluster ring (authority) -->
    <circle cx="360" cy="400" r="118" stroke="#c9a227" stroke-width="1.1" opacity="0.7"/>
    <circle cx="360" cy="400" r="118" stroke="#c9a227" stroke-width="0.4" opacity="0.35"
            stroke-dasharray="2 6"/>
    <!-- Edges inside the bound region -->
    <g stroke="#f0f7f6" stroke-width="0.85" opacity="0.55">
      <path d="M320 340 L360 400 L410 350"/>
      <path d="M300 420 L360 400 L400 450"/>
      <path d="M340 470 L360 400"/>
      <path d="M360 400 L420 410"/>
    </g>
    <!-- Hollow nodes — outside -->
    <g stroke="#b8ddd8" stroke-width="0.9" fill="#146666" fill-opacity="0.35" opacity="0.75">
      <circle cx="72" cy="120" r="4.5"/>
      <circle cx="148" cy="210" r="4"/>
      <circle cx="118" cy="320" r="3.5"/>
      <circle cx="240" cy="168" r="4"/>
      <circle cx="310" cy="240" r="3.5"/>
      <circle cx="520" cy="96" r="4"/>
      <circle cx="460" cy="180" r="4"/>
      <circle cx="510" cy="260" r="3.5"/>
      <circle cx="560" cy="340" r="3.5"/>
      <circle cx="490" cy="400" r="4"/>
      <circle cx="540" cy="480" r="3.5"/>
      <circle cx="80" cy="520" r="4"/>
      <circle cx="150" cy="560" r="3.5"/>
      <circle cx="120" cy="640" r="3.5"/>
      <circle cx="200" cy="700" r="3.5"/>
      <circle cx="280" cy="650" r="4"/>
      <circle cx="360" cy="720" r="3.5"/>
      <circle cx="40" cy="400" r="3"/>
      <circle cx="90" cy="450" r="3"/>
      <circle cx="580" cy="600" r="3.5"/>
      <circle cx="500" cy="640" r="3.5"/>
      <circle cx="560" cy="700" r="3"/>
    </g>
    <!-- Hollow nodes — inside bound cluster -->
    <g stroke="#c9a227" stroke-width="1" fill="#0d3d3d" fill-opacity="0.55" opacity="0.95">
      <circle cx="320" cy="340" r="5"/>
      <circle cx="360" cy="400" r="6"/>
      <circle cx="410" cy="350" r="4.5"/>
      <circle cx="300" cy="420" r="4"/>
      <circle cx="400" cy="450" r="4.5"/>
      <circle cx="340" cy="470" r="4"/>
      <circle cx="420" cy="410" r="4"/>
    </g>
  </g>
</svg>
"""


def build_book_html(meta: dict, chapters: list[dict], year: int) -> str:
    title = html.escape(meta["title"])
    subtitle = html.escape(meta.get("subtitle") or "")
    author = html.escape(meta.get("author") or "Yi Zhang")
    site = html.escape(meta.get("site_url") or "https://iamyi.net")
    version = meta.get("version")
    version_date = meta.get("version_date")
    if version and version_date:
        version_html = (
            f'<p>Version {html.escape(str(version))} · '
            f'{html.escape(str(version_date))}</p>'
        )
    elif version:
        version_html = f'<p>Version {html.escape(str(version))}</p>'
    else:
        version_html = ""

    cover_style = (meta.get("cover_style") or "default").strip().lower()
    cover_classes = "cover"
    cover_art = ""
    if cover_style == "trace-lattice":
        cover_classes = "cover cover-trace-lattice"
        cover_art = TRACE_LATTICE_SVG

    toc_items = []
    body_parts = []
    for i, ch in enumerate(chapters):
        anchor = f"ch-{i:03d}"
        toc_items.append(
            f'<li><a href="#{anchor}">{html.escape(ch["title"])}</a></li>'
        )
        body_parts.append(
            f'<section class="chapter" id="{anchor}">\n{ch["html"]}\n</section>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>{title}</title>
  <style>{BOOK_CSS}</style>
</head>
<body>
  <section class="{cover_classes}">
    {cover_art}
    <div class="cover-inner">
      <p class="cover-brand">iamyi.net · Minibook</p>
      <h1>{title}</h1>
      <p class="subtitle">{subtitle}</p>
      <div class="meta">
        <p>{author}</p>
        {version_html}
        <p>{site}</p>
      </div>
    </div>
  </section>

  <section class="copyright">
    <h1>Copyright</h1>
    <p>Copyright © {year} {author}.</p>
    <p>Unless noted otherwise, this minibook is licensed under the
    <a href="https://creativecommons.org/licenses/by/4.0/">Creative Commons
    Attribution 4.0 International License (CC BY 4.0)</a>.</p>
    <p>You are free to share and adapt the material for any purpose, including
    commercially, provided you give appropriate credit.</p>
    <p>Published at <a href="{site}">{site}</a>. This PDF is a compiled snapshot
    of the online topic chapters; the website may be newer.</p>
  </section>

  <section class="toc">
    <h1>Contents</h1>
    <ul>
      {"".join(toc_items)}
    </ul>
  </section>

  {"".join(body_parts)}
</body>
</html>
"""


def generate_book(topic: str, meta: dict, nav: list, *, force: bool = False) -> Path | None:
    from weasyprint import HTML

    rel_paths = chapter_paths_for_topic(nav, topic)
    if not rel_paths:
        print(f"skip {topic}: no chapters in nav", file=sys.stderr)
        return None

    out_dir = DOCS / "minibooks" / topic / "minibook"
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_name = meta.get("pdf_filename") or f"{topic}.pdf"
    pdf_path = out_dir / pdf_name

    sources = [MKDOCS_YML, BOOKS_YML, Path(__file__)]
    chapters: list[dict] = []
    for rel in rel_paths:
        path = DOCS / rel
        if not path.exists():
            print(f"warn: missing {rel}", file=sys.stderr)
            continue
        sources.append(path)
        raw = path.read_text(encoding="utf-8")
        body = strip_front_matter(raw)
        title = chapter_title(body, path.stem)
        chapters.append({"title": title, "html": md_to_html(body), "path": path})

    if not chapters:
        print(f"skip {topic}: no readable chapters", file=sys.stderr)
        return None

    if not force and not needs_rebuild(pdf_path, sources):
        print(f"up-to-date {pdf_path.relative_to(ROOT)}")
        return pdf_path

    site_meta = {
        **meta,
        "author": "Yi Zhang",
        "site_url": "https://iamyi.net",
    }
    book_html = build_book_html(site_meta, chapters, year=date.today().year)
    HTML(string=book_html, base_url=str(DOCS / "minibooks" / topic)).write_pdf(pdf_path)
    print(f"wrote {pdf_path.relative_to(ROOT)} ({len(chapters)} chapters)")
    return pdf_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--book",
        action="append",
        dest="books",
        help="Generate only this minibook slug (repeatable).",
    )
    parser.add_argument("--force", action="store_true", help="Rebuild even if up to date.")
    args = parser.parse_args(argv)

    books = load_yaml(BOOKS_YML)["books"]
    mkdocs = load_yaml(MKDOCS_YML)
    nav = mkdocs.get("nav") or []

    selected = args.books or list(books.keys())
    for book_id in selected:
        if book_id not in books:
            print(f"unknown minibook: {book_id}", file=sys.stderr)
            return 1
        generate_book(book_id, books[book_id], nav, force=args.force)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
