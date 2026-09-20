#!/usr/bin/env bash
# Re-export Talks PPTX → PNG slides for the on-page viewer.
# Requires Microsoft PowerPoint (macOS) and pdftoppm (poppler).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TALKS="$ROOT/docs/talks"

export_one() {
  local stem="$1"
  local dir="$TALKS/${stem}"
  local pptx="$dir/${stem}.pptx"
  local pdf="$TALKS/_tmp-${stem}.pdf"
  local outdir="$dir/slides"

  if [[ ! -f "$pptx" ]]; then
    echo "missing $pptx" >&2
    exit 1
  fi

  echo "Exporting $stem ..."
  osascript <<APPLESCRIPT
tell application "Microsoft PowerPoint"
  activate
  open POSIX file "$pptx"
  delay 2
  save active presentation in POSIX file "$pdf" as save as PDF
  close active presentation saving no
end tell
APPLESCRIPT

  rm -rf "$outdir"
  mkdir -p "$outdir"
  pdftoppm -png -r 144 "$pdf" "$outdir/slide"
  rm -f "$pdf"
  echo "  -> $(ls "$outdir" | wc -l | tr -d ' ') slides in $outdir"
}

export_one "can-llms-do-security-code-review"
export_one "compliance-from-the-perspective-of-security-in-plain-words"
echo "Done. Update data-slide-count on talk pages if slide counts changed."
