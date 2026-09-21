#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# One-time installer for the SOC dashboard.
#
#   ./setup.sh
#
# Creates the virtual environment, installs dependencies and builds the
# offline sample dataset. After this, start the dashboard any time with
# ./run.sh (or by double-clicking start.command on macOS).
# ---------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")"

echo "==> Creating virtual environment (.venv)…"
python3 -m venv .venv
.venv/bin/pip install -U pip >/dev/null

echo "==> Installing dependencies…"
.venv/bin/pip install -r requirements.txt

echo "==> Generating the offline sample dataset…"
.venv/bin/python src/mock_data_generator.py

echo
echo "Setup complete. Start the dashboard with:"
echo "    ./run.sh        (then open http://localhost:8501)"
