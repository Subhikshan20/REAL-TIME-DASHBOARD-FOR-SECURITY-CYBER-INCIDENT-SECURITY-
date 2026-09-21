#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Start the SOC dashboard.
#
#   ./run.sh                     -> http://localhost:8501
#
# On first run this creates a virtual environment, installs the dependencies
# and generates the offline mock dataset, so a single command is enough.
# ---------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")"

VENV=".venv"
PORT="${SOC_PORT:-8501}"

if [ ! -d "$VENV" ]; then
  echo "[setup] creating virtual environment…"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -U pip >/dev/null
  echo "[setup] installing dependencies…"
  "$VENV/bin/pip" install -r requirements.txt
fi

# Generate the offline mock dataset if it does not exist yet.
if [ ! -f "data/wazuh_alerts.json" ]; then
  echo "[setup] generating sample dataset…"
  "$VENV/bin/python" src/mock_data_generator.py
fi

# If the requested port is busy (e.g. a previous run is still up), pick the next
# free one automatically so the launch never fails with a cryptic "Port not
# available" message. Override the starting port with SOC_PORT.
REQ_PORT="$PORT"
PORT="$("$VENV/bin/python" - "$PORT" <<'PY'
import socket, sys

start = int(sys.argv[1])
for p in range(start, start + 20):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", p))
            print(p)
            break
        except OSError:
            continue
else:
    print(start)
PY
)"
if [ "$PORT" != "$REQ_PORT" ]; then
  echo "[run] port ${REQ_PORT} is in use — starting on ${PORT} instead (set SOC_PORT to choose)."
fi

echo "[run] SOC dashboard -> http://localhost:${PORT}   (press Ctrl+C to stop)"
exec "$VENV/bin/streamlit" run src/app.py \
  --server.port="$PORT" --browser.gatherUsageStats=false "$@"
