#!/usr/bin/env bash
# Double-click this file in Finder (macOS) to launch the SOC dashboard.
# It opens your browser automatically once the server is ready.
cd "$(dirname "$0")"

BASE="${SOC_PORT:-8501}"
( # open the browser shortly after the server starts — scan the port range
  # run.sh may auto-select if the base port was busy.
  for _ in $(seq 1 60); do
    for p in $(seq "$BASE" $((BASE + 19))); do
      if curl -fs -o /dev/null "http://localhost:${p}/_stcore/health" 2>/dev/null; then
        open "http://localhost:${p}" 2>/dev/null || true
        exit 0
      fi
    done
    sleep 1
  done
) &

exec ./run.sh
