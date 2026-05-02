#!/usr/bin/env python3
"""Run mkdocs serve and restart cleanly when only mkdocs.yml changes.

Polls mtime of mkdocs.yml (not the whole tree) to avoid extra reload churn from watching
tools/overrides. On config change: stop server, regen indexes, mkdocs build --clean, start again.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MKDOCS_YML = ROOT / "mkdocs.yml"
REGEN = ROOT / "tools" / "regen_indexes.py"
POLL_SEC = 1.0
DEBOUNCE_SEC = 0.35


def regen() -> None:
    r = subprocess.run([sys.executable, str(REGEN)], cwd=ROOT, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"regen_indexes failed with exit {r.returncode}")


def mkdocs_serve_cmd(host: str, extra: list[str]) -> list[str]:
    return [
        sys.executable,
        "-m",
        "mkdocs",
        "serve",
        "-a",
        host,
        "--watch-theme",
        *extra,
    ]


def build_clean() -> None:
    subprocess.run(
        [sys.executable, "-m", "mkdocs", "build", "--clean"],
        cwd=ROOT,
        check=True,
    )


def main() -> int:
    host = os.environ.get("MKDOCS_DEV_ADDR", "127.0.0.1:8000")
    mkdocs_args = sys.argv[1:]

    if not MKDOCS_YML.is_file():
        print(f"Missing {MKDOCS_YML}", file=sys.stderr)
        return 1

    child: subprocess.Popen | None = None
    config_mtime = MKDOCS_YML.stat().st_mtime

    def start() -> None:
        nonlocal child
        child = subprocess.Popen(
            mkdocs_serve_cmd(host, mkdocs_args),
            cwd=ROOT,
        )

    def stop() -> None:
        nonlocal child
        if child is None:
            return
        if child.poll() is not None:
            child = None
            return
        child.terminate()
        try:
            child.wait(timeout=8)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)
        child = None

    regen()
    start()
    try:
        while True:
            time.sleep(POLL_SEC)
            if child is not None and child.poll() is not None:
                rc = child.returncode
                child = None
                return 0 if rc is None else int(rc)

            try:
                m = MKDOCS_YML.stat().st_mtime
            except OSError:
                continue
            if m == config_mtime:
                continue
            time.sleep(DEBOUNCE_SEC)
            try:
                m2 = MKDOCS_YML.stat().st_mtime
            except OSError:
                continue
            if m2 != m:
                continue
            config_mtime = m2
            print(
                "\n[dev_serve] mkdocs.yml changed — regen, build --clean, restart serve\n",
                file=sys.stderr,
                flush=True,
            )
            stop()
            regen()
            build_clean()
            start()
    except KeyboardInterrupt:
        stop()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
