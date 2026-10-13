#!/usr/bin/env sh
# GrizzDog-AI launcher for Mac/Linux: updates to the newest release, then starts.
# Options: --docker  --kiosk  --no-update  --channel release|main|off  --check
cd "$(dirname "$0")" || exit 1
if command -v python3 >/dev/null 2>&1; then exec python3 start.py "$@"; fi
if command -v python >/dev/null 2>&1; then exec python start.py "$@"; fi
echo "Python 3 was not found. Install it from https://www.python.org/downloads/" >&2
exit 1
