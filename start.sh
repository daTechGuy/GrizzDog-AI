#!/usr/bin/env sh
# GrizzDog-AI launcher for Mac/Linux: updates to the newest release, then starts.
# Options: --docker  --kiosk  --no-update  --channel release|main|off  --check
cd "$(dirname "$0")" || exit 1
# Ensure Homebrew environment is available on macOS if installed
if [ -x "/opt/homebrew/bin/brew" ]; then
    eval "$(/opt/homebrew/bin/brew shellenv 2>/dev/null)"
elif [ -x "/usr/local/bin/brew" ]; then
    eval "$(/usr/local/bin/brew shellenv 2>/dev/null)"
fi

# Locate Python 3 binary
PYTHON_BIN=""
if [ -x ".venv/bin/python" ]; then
    PYTHON_BIN=".venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
fi

if [ -z "$PYTHON_BIN" ]; then
    echo "Python 3 was not found. Install it from https://www.python.org/downloads/ or via 'brew install python'" >&2
    exit 1
fi

# Auto-bootstrap virtual environment if missing (native run)
case "$*" in
    *--docker*) ;;
    *)
        if [ ! -x ".venv/bin/python" ]; then
            echo "[bootstrap] Setting up Python virtual environment (.venv)..."
            "$PYTHON_BIN" -m venv .venv
            if [ -x ".venv/bin/pip" ]; then
                echo "[bootstrap] Installing dependencies from requirements.txt..."
                .venv/bin/pip install --upgrade pip --quiet 2>/dev/null || true
                .venv/bin/pip install -r requirements.txt --quiet
            fi
        fi
        ;;
esac

# Use the project's virtual environment automatically if one exists
if [ -x ".venv/bin/python" ]; then exec .venv/bin/python start.py "$@"; fi
exec "$PYTHON_BIN" start.py "$@"
