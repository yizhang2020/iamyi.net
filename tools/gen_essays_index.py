#!/usr/bin/env python3
"""Regenerate docs/essays/index.md (Essays), categorized list."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

from essay_catalog import (  # noqa: E402
    collect_essays,
    group_essays,
    load_config,
    write_if_changed,
)

OUT = REPO_ROOT / "docs" / "essays" / "index.md"


def main() -> int:
    cfg = load_config()
    essays = collect_essays(cfg)
    grouped = group_essays(essays, cfg)

    lines = [
        "---",
        'title: "Essays"',
        "description: Categorized essays and notes on security engineering practice (regenerated on each site build).",
        "---",
        "",
        "# Essays",
        "",
        "Shorter or more opinionated pieces: how security teams interact with delivery, trade-offs, "
        "tooling, and day-to-day engineering—not always tied to a single product or incident.",
        "",
        "This page is regenerated on each site build from Markdown notes in this folder "
        "(categories and one-line summaries live in `tools/home_browse.yml`).",
        "",
    ]
    for category, items in grouped:
        lines.append(f"## {category}")
        lines.append("")
        for e in items:
            lines.append(f"- [{e.title}]({e.link}) — {e.summary}")
        lines.append("")

    if not essays:
        lines.append("_No articles yet in this folder._")
        lines.append("")

    lines.extend(
        [
            "If a thread grows into a long-running series, consider moving it under "
            "[Minibooks](../minibooks/genai-ml-security/index.md) or "
            "[Incidents](../incidents/index.md) instead.",
            "",
        ]
    )
    write_if_changed(OUT, "\n".join(lines), f"{len(essays)} essays")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
