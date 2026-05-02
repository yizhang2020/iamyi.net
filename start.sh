#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# Local dev server:
# - `tools/dev_serve.py` runs `mkdocs serve` and polls only mkdocs.yml (mtime). When the config
#   file changes, it stops the server, runs regen_indexes, `mkdocs build --clean`, and starts
#   serve again so theme/plugins/nav changes actually apply (livereload alone can leave a stale UI).
# - Doc edits still use MkDocs’ normal watch of docs/ + mkdocs.yml; hooks run on each rebuild via
#   mkdocs_hooks.py.
# - `watch:` in mkdocs.yml includes `overrides/` for theme hot-reload; `tools/` is not watched
#   to avoid noisy rebuilds when editing generators. For hook/tool changes, edit mkdocs.yml or
#   rely on dev_serve’s mkdocs.yml restart.

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck source=/dev/null
source .venv/bin/activate
pip install -q -r requirements.txt

exec python "$ROOT/tools/dev_serve.py" "$@"
