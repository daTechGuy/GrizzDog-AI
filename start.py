#!/usr/bin/env python3
"""
GrizzDog-AI launcher: update, then start.

    start.bat                      (Windows)      ./start.sh   (Mac/Linux)
    python start.py [options]

Options:
    --docker           start the Docker stack (docker compose up -d) instead of running natively
    --kiosk            booth mode (sets GRIZZDOG_KIOSK=1): booth-only page, no editing
    --no-update        start without updating (same as GRIZZDOG_NO_UPDATE=1)
    --channel NAME     release (default, newest tagged version), main, or off
    --check            only say whether an update is available, then exit

The update step never blocks startup: if you're offline or the update fails
its self-check, the app starts on the version you already have.
Details: lab/scripts/update.py
"""

import argparse
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "lab" / "scripts"))
import update  # noqa: E402


def run_update(args):
    argv = []
    if args.no_update:
        argv += ["--channel", "off"]
    elif args.channel:
        argv += ["--channel", args.channel]
    if args.check:
        argv.append("--check")
    if args.docker:
        argv.append("--docker")
    try:
        return update.main(argv, repo=ROOT)
    except Exception as e:  # an updater bug must never stop the app from starting
        print(f"[update] Skipped, updater error: {e}")
        return 0


def show_version():
    try:
        import json
        v = json.loads((ROOT / ".grizzdog" / "version.json").read_text(encoding="utf-8"))
        channel = v.get("channel", "?")
        print(f"GrizzDog-AI {v.get('version', 'unknown')}  ({'updates off' if channel == 'off' else channel + ' channel'})")
    except (OSError, ValueError):
        pass


def start_docker(updated):
    for cmd in (["docker", "compose", "up", "-d"], ["docker", "compose", "restart", "web"] if updated else None):
        if cmd and subprocess.call(cmd, cwd=ROOT) != 0:
            print("Docker did not start. Is Docker Desktop running?")
            return 1
    port = os.environ.get("WEB_PORT", "5000")
    print(f"GrizzDog-AI is starting at http://localhost:{port}  (stop it with: docker compose down)")
    return 0


def start_native():
    missing = [m for m in ("flask", "ollama", "requests") if importlib.util.find_spec(m) is None]
    if missing:
        print(f"Missing Python packages: {', '.join(missing)}\nInstall them with:  python -m pip install -r requirements.txt")
        return 1
    try:  # friendly hint only; never builds (the base model download is large)
        cp = subprocess.run([sys.executable, str(ROOT / "lab" / "scripts" / "build_models.py"), "--check"],
                            capture_output=True, text=True, timeout=30)
        first = (cp.stdout.strip().splitlines() or [""])[0]
        if cp.returncode == 1 and "lab models present" in first:
            print(f"[models] {first} Build them with: python lab/scripts/build_models.py")
    except (OSError, subprocess.TimeoutExpired):
        pass
    port = os.environ.get("GRIZZDOG_PORT") or os.environ.get("EDUGUARD_PORT") or "5000"
    print(f"Starting the gateway at http://localhost:{port}  (Ctrl+C to stop)")
    try:
        return subprocess.call([sys.executable, str(ROOT / "lab" / "scripts" / "secure_gateway.py")], cwd=ROOT)
    except KeyboardInterrupt:
        return 0


def main():
    ap = argparse.ArgumentParser(description="Update and start GrizzDog-AI.")
    ap.add_argument("--docker", action="store_true")
    ap.add_argument("--kiosk", action="store_true")
    ap.add_argument("--no-update", action="store_true")
    ap.add_argument("--channel", choices=["release", "main", "off"])
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    os.chdir(ROOT)
    if args.kiosk:
        os.environ["GRIZZDOG_KIOSK"] = "1"

    code = run_update(args)
    show_version()
    if args.check:
        return 0
    return start_docker(code == update.EXIT_UPDATED) if args.docker else start_native()


if __name__ == "__main__":
    sys.exit(main())
