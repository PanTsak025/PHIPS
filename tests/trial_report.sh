#!/bin/bash
# Summarise a collection run in one block you can paste for review.
#   sudo tests/trial_report.sh [DIR]          (default DIR = /var/lib/phips)
# Stop the service first (sudo systemctl stop phips-collector) so the last file is closed cleanly.
cd "$(dirname "$0")/.."
DIR="${1:-/var/lib/phips}"
echo "===== machine"
uname -r; nproc; free -h | sed -n 2p; df -h "$DIR" | tail -1
echo "===== service log (start, file changes, drops, errors)"
journalctl -u phips-collector --no-pager -o cat 2>/dev/null \
  | grep -E "running|writing|dropped|failed|error" | tail -15
echo "===== files"
ls -l --time-style=+%F_%T "$DIR"
du -sh "$DIR"
echo "===== validator"
python3 tests/validate_capture.py "$DIR"/*.jsonl* 2>&1
echo "===== graph"
python3 graph_builder.py "$DIR"/*.jsonl* 2>&1 | head -30
