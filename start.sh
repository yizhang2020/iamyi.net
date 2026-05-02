#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="mkdocs.yml"

# You can tweak these if needed
ZEN_CMD=("zensical" "serve")
WATCH_PATHS=("mkdocs.yml")

# Also restart when nav/theme/plugin config changes elsewhere, if you keep them:
# WATCH_PATHS+=("requirements.txt" "main.py")

run_server() {
  # Run zensical serve, hide output unless it errors.
  # If it exits non-zero, print the captured log.
  local log_file
  log_file="$(mktemp -t zensical_serve_XXXXXX.log)"

  echo "Starting: ${ZEN_CMD[*]} (output suppressed; errors will be shown)"
  # Note: use stdbuf if you see buffering issues; not always available on mac.
  "${ZEN_CMD[@]}" >"$log_file" 2>&1 &
  local pid=$!

  # Wait for process to exit (normally you won't hit this unless it errors or is killed)
  wait "$pid" || {
    echo "❌ zensical exited with error. Showing logs:"
    cat "$log_file"
    rm -f "$log_file"
    return 1
  }

  rm -f "$log_file"
}

kill_server() {
  local pid="$1"
  if kill -0 "$pid" >/dev/null 2>&1; then
    echo "Stopping server (pid=$pid)..."
    kill "$pid" >/dev/null 2>&1 || true
    # Give it a moment to exit
    sleep 0.3
    # Force kill if needed
    kill -9 "$pid" >/dev/null 2>&1 || true
  fi
}

start_loop() {
  local log_file
  log_file="$(mktemp -t zensical_serve_XXXXXX.log)"

  echo "Starting: ${ZEN_CMD[*]} (output suppressed; errors will be shown)"
  "${ZEN_CMD[@]}" >"$log_file" 2>&1 &
  local pid=$!
  echo "Server PID: $pid"

  # Watch mkdocs.yml; restart on change
  # -o emits an event count; -1 is not used because we want continuous
  fswatch -o "${WATCH_PATHS[@]}" | while read -r _; do
    echo "Detected change in mkdocs.yml -> restarting..."
    kill_server "$pid"

    # Start again (new temp log each time)
    rm -f "$log_file"
    log_file="$(mktemp -t zensical_serve_XXXXXX.log)"
    "${ZEN_CMD[@]}" >"$log_file" 2>&1 &
    pid=$!
    echo "Server PID: $pid"
  done
}

start_loop
