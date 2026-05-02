#!/usr/bin/env python3
"""Regenerate derived Markdown indexes (same logic as mkdocs_hooks.on_pre_build)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPTS: list[tuple[str, bool]] = [
    ("tools/gen_cases_index.py", False),
    ("tools/gen_security_musings_index.py", True),
    ("tools/gen_latest_writing.py", True),
]


def run(root: Path) -> int:
    py = sys.executable
    for rel, strict in SCRIPTS:
        r = subprocess.run([py, str(root / rel)], cwd=root, check=False)
        if strict and r.returncode != 0:
            print(f"regen_indexes: failed ({r.returncode}): {rel}", file=sys.stderr)
            return r.returncode
    return 0


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    return run(root)


if __name__ == "__main__":
    raise SystemExit(main())
