#!/usr/bin/env python3
"""Split Ch4 mini-chapters: guiding body vs code-density appendix.

Body keeps: definition, characteristics, Python sample, walkthrough, risk,
Python-focused fix, verify, references (+ appendix pointer).

Appendix keeps: payloads/abuse scenarios, language sinks, other-language
vulnerable examples, full multi-language fix section.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BOOK = REPO / "docs" / "minibooks" / "security-code-review"
APPENDIX_DIR = BOOK / "appendix" / "code-level-reference"

MOVE_SECTIONS = {
    "Attack Payloads",
    "Abuse Scenarios",
    "Language-Specific Sinks and Dangerous APIs",
    "Vulnerable Examples in Other Languages",
}

# Full Fix goes to appendix; Python-only excerpt stays in body.
FIX_HEADING = "Fix: Safer Patterns and Libraries to Use"


def split_front_matter(text: str) -> tuple[str, str]:
    if not text.startswith("---"):
        return "", text
    end = text.find("\n---\n", 3)
    if end < 0:
        return "", text
    fm = text[: end + 5]
    body = text[end + 5 :]
    return fm, body


def split_h2_sections(body: str) -> list[tuple[str | None, str]]:
    """Return [(heading_or_None, content_including_heading_line)]."""
    parts: list[tuple[str | None, str]] = []
    matches = list(re.finditer(r"^## (.+)$", body, re.M))
    if not matches:
        return [(None, body)]
    if matches[0].start() > 0:
        parts.append((None, body[: matches[0].start()]))
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        parts.append((m.group(1).strip(), body[start:end]))
    return parts


def extract_python_fix(fix_section: str) -> str | None:
    """Pull ### Python … until next ### or end of section (without ## heading)."""
    # Drop the ## Fix heading line
    lines = fix_section.splitlines(keepends=True)
    if not lines:
        return None
    content = "".join(lines[1:])  # after ## line
    m = re.search(r"^### Python\b.*$", content, re.M)
    if not m:
        return None
    rest = content[m.start() :]
    next_h = re.search(r"^### (?!Python\b).+$", rest, re.M)
    if next_h:
        rest = rest[: next_h.start()]
    return rest.rstrip() + "\n"


def chapter_num_title(title_heading: str) -> tuple[str, str]:
    """'4.1 - Review Stored XSS' -> ('4.1', 'Review Stored XSS')."""
    m = re.match(r"^(4\.\d+)\s*[-–—]\s*(.+)$", title_heading)
    if m:
        return m.group(1), m.group(2).strip()
    return "", title_heading


def process_file(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    fm, body = split_front_matter(text)
    sections = split_h2_sections(body)

    preamble = ""
    title_heading = None
    kept: list[str] = []
    moved: list[str] = []
    fix_full: str | None = None
    python_fix: str | None = None
    refs: str | None = None

    for heading, content in sections:
        if heading is None:
            preamble = content
            continue
        if re.match(r"^4\.\d+", heading):
            title_heading = heading
            kept.append(content)
            continue
        if heading in MOVE_SECTIONS:
            moved.append(content)
            continue
        if heading == FIX_HEADING:
            fix_full = content
            python_fix = extract_python_fix(content)
            continue
        if heading == "Reference":
            refs = content
            continue
        kept.append(content)

    if not title_heading:
        raise ValueError(f"no chapter title in {path.name}")
    if not moved and not fix_full:
        raise ValueError(f"nothing to move in {path.name}")

    num, short = chapter_num_title(title_heading)
    appendix_slug = path.name  # keep same filename for 1:1 mapping
    appendix_rel = f"appendix/code-level-reference/{appendix_slug}"
    chapter_rel = path.name

    # Rebuild body in teaching order.
    title_block = None
    early: list[str] = []  # What + Characteristics
    middle: list[str] = []  # Sample, Walkthrough, Risk
    verify_block: str | None = None
    other_kept: list[str] = []

    for content in kept:
        first = content.lstrip().splitlines()[0] if content.strip() else ""
        h = first[3:].strip() if first.startswith("## ") else ""
        if re.match(r"^4\.\d+", h):
            title_block = content
        elif h.startswith("What This Vulnerability Is") or h.startswith(
            "Vulnerability Characteristics"
        ):
            early.append(content)
        elif h == "Verify During Review":
            verify_block = content
        elif h in {
            "Sample Vulnerable Code in Python",
            "Step-by-Step Review Walkthrough",
            "Risk Impact Analysis",
        }:
            middle.append(content)
        else:
            other_kept.append(content)

    pointer = (
        "## Code Reference (Appendix)\n\n"
        "Payloads, language-specific sinks, multi-language vulnerable examples, "
        "and full fix catalogs live in the appendix so this chapter stays focused "
        "on how we review the pattern.\n\n"
        "**Open the appendix:** "
    )
    if num:
        pointer += (
            f"[{num} code reference — {short}]({appendix_rel}).\n"
        )
    else:
        pointer += f"[Code reference]({appendix_rel}).\n"

    fix_block = ""
    if python_fix:
        fix_block = (
            f"## {FIX_HEADING}\n\n"
            "The primary walkthrough language is Python. For Java, C#, Go, and other "
            "stack-specific fixes, see the "
            f"[appendix code reference]({appendix_rel}).\n\n"
            f"{python_fix}"
        )
    elif fix_full:
        fix_block = (
            f"## {FIX_HEADING}\n\n"
            "Safer patterns and library-level fixes (all languages) are collected in the "
            f"[appendix code reference]({appendix_rel}).\n"
        )

    ref_block = ""
    if refs:
        ref_lines = refs.splitlines(keepends=True)
        appendix_bullet = (
            f"- Appendix — [{num} code reference]({appendix_rel}): "
            "payloads, sinks, multi-language examples and fixes\n"
            if num
            else f"- Appendix — [code reference]({appendix_rel})\n"
        )
        if ref_lines:
            ref_block = "".join([ref_lines[0], "\n", appendix_bullet] + ref_lines[1:])
        else:
            ref_block = refs

    pieces: list[str] = []
    if fm:
        pieces.append(fm.rstrip() + "\n")
    if preamble.strip():
        pieces.append(preamble.rstrip() + "\n")
    if title_block:
        pieces.append(title_block.rstrip() + "\n")
    pieces.extend(p.rstrip() + "\n" for p in early)
    pieces.append(pointer.rstrip() + "\n")
    pieces.extend(p.rstrip() + "\n" for p in middle)
    if fix_block:
        pieces.append(fix_block.rstrip() + "\n")
    if verify_block:
        pieces.append(verify_block.rstrip() + "\n")
    pieces.extend(p.rstrip() + "\n" for p in other_kept)
    if ref_block:
        pieces.append(ref_block.rstrip() + "\n")

    new_body = "\n".join(pieces)
    new_body = re.sub(r"\n{3,}", "\n\n", new_body)
    if not new_body.endswith("\n"):
        new_body += "\n"

    # --- appendix ---
    app_title = f"{num} Code Reference — {short}" if num else f"Code Reference — {short}"
    app_fm = (
        "---\n"
        f'title: "{app_title}"\n'
        "description: >\n"
        f"  Payloads, language sinks, multi-language examples, and fixes for {short}.\n"
        "---\n\n"
    )
    back = (
        f"# {app_title}\n\n"
        "This appendix supports the guiding chapter "
        f"**[{title_heading}](../../{chapter_rel})**. "
        "Use the chapter for review method and the walkthrough; use this page when "
        "you need payloads, sink catalogs, or stack-specific code.\n\n"
        f"**Back to chapter:** [{title_heading}](../../{chapter_rel})\n\n"
    )
    app_sections = moved[:]
    if fix_full:
        app_sections.append(fix_full)
    app_body = app_fm + back + "\n".join(s.rstrip() + "\n\n" for s in app_sections)
    app_body = re.sub(r"\n{3,}", "\n\n", app_body)
    if not app_body.endswith("\n"):
        app_body += "\n"

    APPENDIX_DIR.mkdir(parents=True, exist_ok=True)
    app_path = APPENDIX_DIR / appendix_slug
    app_path.write_text(app_body, encoding="utf-8")
    path.write_text(new_body, encoding="utf-8")

    return {
        "chapter": path.name,
        "appendix": str(app_path.relative_to(REPO)),
        "moved_sections": len(moved) + (1 if fix_full else 0),
        "num": num,
        "short": short,
        "title_heading": title_heading,
    }


def write_appendix_index(results: list[dict]) -> None:
    lines = [
        "---",
        'title: "Appendix — Code-Level Reference"',
        "description: >",
        "  Payloads, language sinks, multi-language examples, and fixes for",
        "  Chapter 4 vulnerability families.",
        "---",
        "",
        "# Appendix — Code-Level Reference",
        "",
        "This appendix holds the **code-density** material for Part III: attack "
        "payloads, language-specific sinks, multi-language vulnerable examples, "
        "and full fix catalogs.",
        "",
        "The [Chapter 4 overview](../../4-review-code-level-vulnerabilities.md) "
        "and each mini-chapter teach how we review the pattern. Open a row below "
        "when you need stack-specific detail during a real review.",
        "",
        "| Chapter | Guiding page | Code reference |",
        "| --- | --- | --- |",
    ]
    for r in results:
        lines.append(
            f"| {r['num']} {r['short']} | "
            f"[{r['title_heading']}](../../{r['chapter']}) | "
            f"[Appendix]({r['chapter']}) |"
        )
    lines.append("")
    (APPENDIX_DIR / "index.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    files = sorted(BOOK.glob("4-*-review-*.md"))
    if not files:
        print("no chapters found", file=sys.stderr)
        return 1
    results = []
    for path in files:
        info = process_file(path)
        results.append(info)
        print(f"split {path.name} -> appendix ({info['moved_sections']} sections)")
    write_appendix_index(results)
    print(f"wrote {APPENDIX_DIR / 'index.md'} ({len(results)} entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
