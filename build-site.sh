#!/usr/bin/env bash
# Follows build-this-site.md: local env + build. Skips creating/pushing a GitHub repo.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# Canonical deps for this site (keeps requirements.txt in sync with build-this-site.md).
cat > requirements.txt <<'EOF'
zensical
mkdocs
mkdocs-material
pymdown-extensions
mkdocs-git-revision-date-localized-plugin
EOF

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck source=/dev/null
source .venv/bin/activate

pip install -r requirements.txt
python tools/gen_cases_index.py || true
mkdocs build --clean

echo "Built static site into: $ROOT/site/"
