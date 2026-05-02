"""MkDocs hooks: regenerate derived Markdown before each build (serve live-reload and mkdocs build).

Runs all index generators so `mkdocs serve` stays in sync. Generators skip writing when output is
unchanged so `docs/includes/latest-writing.md` does not retrigger live reload in a tight loop.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def on_pre_build(config):
    root = Path(config["config_file_path"]).resolve().parent
    r = subprocess.run(
        [sys.executable, str(root / "tools" / "regen_indexes.py")],
        cwd=root,
        check=False,
    )
    if r.returncode != 0:
        raise RuntimeError(f"regen_indexes failed ({r.returncode})")
