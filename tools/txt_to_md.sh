#!/usr/bin/env bash
# Rename a .txt file to .md with the same basename (content unchanged; structure preserved).
# For plain-text-in-.md conversion, use the Cursor command: .cursor/commands/txt-to-md-rebuild.md
#
# Then refresh all index generators and rebuild the static site.
#
# Usage:
#   ./tools/txt_to_md.sh path/inside/repo/file.txt
#   ./tools/txt_to_md.sh                    # prompts for the path
#
# Paths without a leading / are resolved relative to the repository root.

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ $# -ge 1 ]]; then
  TXT=$1
else
  read -r -p "Enter path to .txt file (relative to repo root or absolute): " TXT
fi

# trim leading/trailing whitespace
TXT="${TXT#"${TXT%%[![:space:]]*}"}"
TXT="${TXT%"${TXT##*[![:space:]]}"}"

if [[ -z "$TXT" ]]; then
  echo "No file path given." >&2
  exit 1
fi

if [[ "$TXT" != /* ]]; then
  TXT="$ROOT/${TXT#./}"
fi

if [[ ! -f "$TXT" ]]; then
  echo "File not found: $TXT" >&2
  exit 1
fi

ext_lc=$(printf '%s' "${TXT##*.}" | tr '[:upper:]' '[:lower:]')
if [[ "$ext_lc" != "txt" ]]; then
  echo "Expected a .txt file: $TXT" >&2
  exit 1
fi

# Same basename, .md extension (e.g. foo.txt → foo.md)
base="${TXT%.*}"
MD="${base}.md"

if [[ -f "$MD" ]]; then
  echo "Refusing to overwrite existing file: $MD" >&2
  echo "Remove or rename the .md file first." >&2
  exit 1
fi

mv -- "$TXT" "$MD"
echo "Renamed (structure preserved): $MD"

if [[ -f .venv/bin/activate ]]; then
  # shellcheck source=/dev/null
  source .venv/bin/activate
fi

python tools/gen_cases_index.py || true
python tools/gen_security_musings_index.py
python tools/gen_latest_writing.py
mkdocs build --clean

echo "Site rebuilt under: $ROOT/site/"
