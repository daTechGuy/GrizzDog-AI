#!/usr/bin/env python3
"""
GrizzDog-AI Updater
===================
Brings this checkout up to the newest published version, safely. It is run
by the launcher (start.py / start.bat / start.sh) before the app starts, and
can also be run on its own.

Channels (GRIZZDOG_UPDATE_CHANNEL or --channel):
  release  (default) Follow the newest release tag (vMAJOR.MINOR.PATCH) that
                     is part of the main branch. Half-finished work on main is
                     never picked up. No tags yet = nothing to do.
  main               Follow the tip of origin/main.
  off                Never touch anything (same as GRIZZDOG_NO_UPDATE=1).

What it guarantees:
  * Only fast-forwards. It never uses reset on your work, never merges, and
    leaves a checkout alone if it has commits that are not published.
  * Student-edited files (filter_rules.py, rules.json, lab/modelfiles/*) are
    backed up to .grizzdog/backups/, the update is applied, and the edited
    copies are put back, so students keep their work across updates.
    If upstream also changed one of those files you are told so.
  * Any other uncommitted change in a tracked file skips the update.
  * After updating, the new code is compile-checked and (when Flask is
    installed) smoke-tested on the pristine files. If that fails the update
    is rolled back and that release is not retried.
  * No network, no git, or a ZIP download = it says so and the app starts
    on the current version.

Usage:
    python lab/scripts/update.py              # update, then exit
    python lab/scripts/update.py --check      # report only, change nothing
    python lab/scripts/update.py --channel main
Exit code: 0 = nothing changed / skipped, 10 = updated, 12 = rolled back.
(Older EDUGUARD_* names also work.)
Optional: GRIZZDOG_REQUIRE_SIGNED_TAGS=1 only accepts tags `git verify-tag` trusts.
"""

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_REPO = Path(__file__).resolve().parents[2]
STATE_DIR = ".grizzdog"
# Files students edit through the Defense Studio or by hand.
USER_FILES = ("lab/scripts/filter_rules.py", "policies/rules.json")
USER_DIRS = ("lab/modelfiles/",)
TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
EXIT_UPDATED = 10
EXIT_ROLLED_BACK = 12
BACKUPS_TO_KEEP = 5
FETCH_TIMEOUT = 30


def _truthy(value):
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _env(suffix):
    """GRIZZDOG_<suffix>, falling back to the legacy EDUGUARD_<suffix>."""
    return os.environ.get("GRIZZDOG_" + suffix) or os.environ.get("EDUGUARD_" + suffix) or ""


# ---------------------------------------------------------------- git helpers
def git(repo, *args, timeout=60):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", LC_ALL="C")
    try:
        return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", "timed out")
    except FileNotFoundError:
        return subprocess.CompletedProcess(args, 127, "", "git is not installed")


def ok(cp):
    return cp.returncode == 0


def out(cp):
    return (cp.stdout or "").strip()


def rev(repo, ref):
    cp = git(repo, "rev-parse", "--verify", "-q", ref + "^{commit}")
    return out(cp) if ok(cp) else None


def is_ancestor(repo, a, b):
    return ok(git(repo, "merge-base", "--is-ancestor", a, b))


def is_user_path(path):
    return path in USER_FILES or any(path.startswith(d) for d in USER_DIRS)


def tracked_changes(repo):
    """Paths of tracked files with uncommitted changes (untracked ignored)."""
    cp = git(repo, "status", "--porcelain", "-z", "--untracked-files=no")
    entries = (cp.stdout or "").split("\0")
    paths, i = [], 0
    while i < len(entries):
        e = entries[i]
        i += 1
        if len(e) < 4:
            continue
        if e[0] in "RC":
            i += 1  # skip the "original path" field
        paths.append(e[3:])
    return paths


def upstream_ref(repo):
    for cand in ("origin/main", "origin/master"):
        if rev(repo, cand):
            return cand
    return None


def newest_release(repo, upstream, require_signed, notes):
    tags = []
    for t in (git(repo, "tag", "--list").stdout or "").split():
        m = TAG_RE.match(t)
        if m:
            tags.append((tuple(int(x) for x in m.groups()), t))
    for _ver, tag in sorted(tags, reverse=True):
        if upstream and not is_ancestor(repo, tag + "^{commit}", upstream):
            continue  # tag on some other branch
        if require_signed and not ok(git(repo, "verify-tag", tag)):
            notes.append(f"Skipping {tag}: its signature could not be verified.")
            continue
        return tag
    return None


def describe_version(repo):
    """'v1.2.0', 'v1.2.0+3 (abc1234)' or 'unreleased (abc1234)'."""
    head = rev(repo, "HEAD")
    if not head:
        return "unknown"
    short = head[:7]
    cp = git(repo, "describe", "--tags", "--exact-match", "--match", "v[0-9]*", "HEAD")
    if ok(cp):
        return out(cp)
    cp = git(repo, "describe", "--tags", "--long", "--match", "v[0-9]*", "HEAD")
    m = re.match(r"^(v\d+\.\d+\.\d+)-(\d+)-g[0-9a-f]+$", out(cp)) if ok(cp) else None
    return f"{m.group(1)}+{m.group(2)} ({short})" if m else f"unreleased ({short})"


# ---------------------------------------------------------------- local state
def _state_dir(repo):
    d = Path(repo) / STATE_DIR
    d.mkdir(exist_ok=True)
    return d


def load_state(repo):
    try:
        return json.loads((Path(repo) / STATE_DIR / "update_state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(repo, state):
    try:
        (_state_dir(repo) / "update_state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    except OSError:
        pass


def write_version(repo, channel, status, latest_release):
    """Record what is running. The app (and Docker, which mounts the repo)
    reads this because the container has no git."""
    head = rev(repo, "HEAD")
    if not head:
        return
    branch = out(git(repo, "symbolic-ref", "-q", "--short", "HEAD")) or None
    data = {
        "version": describe_version(repo),
        "commit": head,
        "branch": branch,
        "channel": channel,
        "last_update_status": status,
        "latest_release": latest_release,
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    }
    try:
        (_state_dir(repo) / "version.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass


# ------------------------------------------------- preserving student edits
def backup_user_files(repo, files):
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    root = _state_dir(repo) / "backups"
    dest = root / stamp
    for f in files:
        src = Path(repo) / f
        if src.is_file():
            (dest / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest / f)
    old = sorted(p for p in root.iterdir() if p.is_dir()) if root.exists() else []
    for p in old[:-BACKUPS_TO_KEEP]:
        shutil.rmtree(p, ignore_errors=True)
    return dest


def restore_user_files(repo, backup_dir, files, notes):
    for f in files:
        src = Path(backup_dir) / f
        if not src.is_file():
            continue
        if ok(git(repo, "cat-file", "-e", f"HEAD:{f}")):
            dst = Path(repo) / f
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
        else:
            notes.append(f"{f} no longer exists in this version; your edited copy is kept in {backup_dir}")


# ------------------------------------------------------------ verification
def verify_new_code(repo, install_deps, requirements_changed, notes):
    """Returns (ok, message). Runs on the pristine (unedited) files so a
    student's broken rules can never trigger a rollback."""
    py = sys.executable
    if requirements_changed and install_deps:
        cp = subprocess.run([py, "-m", "pip", "install", "-q", "-r", "requirements.txt"], cwd=repo,
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
        if cp.returncode != 0:
            return False, "could not install the new requirements: " + (cp.stderr or cp.stdout).strip()[-200:]
        notes.append("Installed updated Python requirements.")

    scripts = sorted(str(p) for p in (Path(repo) / "lab" / "scripts").glob("*.py"))
    if scripts:
        cp = subprocess.run([py, "-m", "py_compile", *scripts], cwd=repo, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=120)
        if cp.returncode != 0:
            return False, "a script does not compile: " + (cp.stderr or cp.stdout).strip()[-200:]

    gateway = Path(repo) / "lab" / "scripts" / "secure_gateway.py"
    have_deps = subprocess.run([py, "-c", "import flask, ollama, requests"], capture_output=True).returncode == 0
    if gateway.exists() and have_deps:
        script = ("import sys; sys.path.insert(0, 'lab/scripts'); import secure_gateway as g; c = g.app.test_client();"
                  "assert c.get('/').status_code == 200, 'home page'; assert c.get('/api/benchmark').status_code == 200, 'benchmark'")
        env = dict(os.environ, GRIZZDOG_KIOSK="0", EDUGUARD_KIOSK="0", PYTHONIOENCODING="utf-8")
        cp = subprocess.run([py, "-c", script], cwd=repo, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=120, env=env)
        if cp.returncode != 0:
            return False, "the app failed its start-up check: " + (cp.stderr or cp.stdout).strip()[-300:]
    elif gateway.exists():
        notes.append("Flask/ollama not installed here, so only a compile check was run.")
    return True, "ok"


# ---------------------------------------------------------------- main logic
def run(repo=DEFAULT_REPO, channel="release", check_only=False, require_signed=False, install_deps=True):
    repo = Path(repo)
    notes = []
    res = {"status": "skipped", "from": None, "to": None, "notes": notes, "models_changed": False,
           "requirements_changed": False, "kept_user_files": [], "channel": channel, "latest_release": None}

    def finish(status, message=None):
        res["status"] = status
        if message:
            notes.append(message)
        if not check_only:
            write_version(repo, channel, status, res["latest_release"])
        return res

    if not ok(git(repo, "rev-parse", "--git-dir")):
        return finish("skipped", "Not a git checkout (or git is missing), so updates are off. "
                                 "Clone the repository to get automatic updates.")
    head = rev(repo, "HEAD")
    if not head:
        return finish("skipped", "This checkout has no commits yet.")
    res["from"] = describe_version(repo)

    if channel == "off":
        return finish("skipped", "Updates are off; running the current version.")
    if channel not in ("release", "main"):
        return finish("skipped", f"Unknown update channel '{channel}' (use release, main or off).")

    fetch = git(repo, "fetch", "--tags", "origin", timeout=FETCH_TIMEOUT)
    if not ok(fetch):
        return finish("offline", "Could not reach GitHub (offline?); running the current version.")

    upstream = upstream_ref(repo)
    if channel == "main":
        if not upstream:
            return finish("skipped", "No origin/main branch found.")
        label, target = "latest main", rev(repo, upstream)
    else:
        tag = newest_release(repo, upstream, require_signed, notes)
        res["latest_release"] = tag
        if not tag:
            return finish("no-release", "No release has been published yet (tag one, e.g. v1.0.0); "
                                        "staying on the current version.")
        label, target = tag, rev(repo, tag)
    res["to"] = label

    if head == target:
        return finish("up-to-date", f"Up to date ({res['from']}).")
    if not is_ancestor(repo, head, target):
        if is_ancestor(repo, target, head):
            return finish("ahead", f"This copy ({res['from']}) is newer than {label}; leaving it alone.")
        return finish("diverged", f"This copy has changes that are not in {label}; leaving it alone.")
    if load_state(repo).get("bad_target") == target:
        return finish("known-bad", f"{label} failed its self-check on this computer before; staying on "
                                   f"{res['from']}. It will be retried when a newer release appears.")

    behind = out(git(repo, "rev-list", "--count", f"{head}..{target}"))
    if check_only:
        return finish("update-available", f"Update available: {res['from']} -> {label} ({behind} new commit{'' if behind == '1' else 's'}).")

    changes = tracked_changes(repo)
    other = [p for p in changes if not is_user_path(p)]
    if other:
        shown = ", ".join(other[:5]) + (" ..." if len(other) > 5 else "")
        return finish("dirty", f"Update to {label} skipped: uncommitted changes in {shown}. "
                               "Commit or discard them (git status), then start again.")

    kept = sorted(p for p in changes if is_user_path(p))
    res["kept_user_files"] = kept
    backup_dir = backup_user_files(repo, kept) if kept else None
    try:
        if kept:
            git(repo, "checkout", "HEAD", "--", *kept)  # pristine tree so the update can't conflict
        on_branch = ok(git(repo, "symbolic-ref", "-q", "HEAD"))
        cp = (git(repo, "merge", "--ff-only", target) if on_branch
              else git(repo, "checkout", "--detach", target))
        if not ok(cp):
            return finish("error", f"Update to {label} failed, nothing changed: "
                                   f"{(cp.stderr or cp.stdout).strip()[-200:]}")

        changed = out(git(repo, "diff", "--name-only", head, target)).splitlines()
        res["requirements_changed"] = "requirements.txt" in changed
        res["models_changed"] = any(c.startswith("lab/modelfiles/") for c in changed)

        good, why = verify_new_code(repo, install_deps, res["requirements_changed"], notes)
        if not good:
            git(repo, "reset", "--hard", head)
            save_state(repo, {"bad_target": target, "label": label, "reason": why,
                              "at": datetime.datetime.now().isoformat(timespec="seconds")})
            return finish("rolled-back", f"{label} failed its self-check ({why}); went back to {res['from']}.")

        save_state(repo, {})
        upstream_changed = [p for p in kept if p in changed]
        for p in upstream_changed:
            notes.append(f"{p} changed upstream too; YOUR edited copy was kept. "
                         "(To adopt the new default, restore it with: git checkout -- " + p + ")")
        notes.append(f"Updated {res['from']} -> {label}.")
        return finish("updated")
    finally:
        if backup_dir:
            restore_user_files(repo, backup_dir, kept, notes)
            if kept:
                notes.append(f"Kept your edits to {len(kept)} file(s) (backup in {backup_dir}).")


def rebuild_models(repo, docker, notes):
    """Model files changed upstream: rebuild so Ollama matches. Never pulls
    the multi-GB base model (build_models --no-pull); failures are not fatal."""
    try:
        if docker:
            subprocess.run(["docker", "compose", "up", "-d", "llm"], cwd=repo, capture_output=True, timeout=300)
        cmd = [sys.executable, str(Path(repo) / "lab" / "scripts" / "build_models.py"), "--no-pull"]
        if docker:
            cmd.append("--docker")
        cp = subprocess.run(cmd, cwd=repo, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=900)
        last = (cp.stdout.strip().splitlines() or [""])[-1] if cp.returncode == 0 else (cp.stderr or cp.stdout).strip()
        notes.append("Model files changed upstream. " + (f"Rebuilt: {last}" if cp.returncode == 0 else
                     f"Could not rebuild automatically ({last[-160:]}); run: python lab/scripts/build_models.py"))
    except (OSError, subprocess.TimeoutExpired) as e:
        notes.append(f"Model files changed upstream; run python lab/scripts/build_models.py ({e}).")


def main(argv=None, repo=None):
    ap = argparse.ArgumentParser(description="Update GrizzDog-AI to the newest published version.")
    ap.add_argument("--channel", choices=["release", "main", "off"],
                    help="release (default) = newest vX.Y.Z tag; main = latest main; off = never update")
    ap.add_argument("--check", action="store_true", help="only report whether an update exists; change nothing")
    ap.add_argument("--no-pip", action="store_true", help="don't install requirements after an update")
    ap.add_argument("--docker", action="store_true", help="Docker setup: skip pip, rebuild models inside Docker")
    args = ap.parse_args(argv)

    channel = (args.channel or _env("UPDATE_CHANNEL") or "release").strip().lower()
    if _truthy(_env("NO_UPDATE")):
        channel = "off"
    repo = Path(repo or DEFAULT_REPO)

    res = run(repo, channel, check_only=args.check,
              require_signed=_truthy(_env("REQUIRE_SIGNED_TAGS")),
              install_deps=not (args.no_pip or args.docker))
    if res["status"] == "updated" and res["models_changed"]:
        rebuild_models(repo, args.docker, res["notes"])
    for line in res["notes"]:
        print("[update] " + line)
    if res["status"] == "updated":
        return EXIT_UPDATED
    if res["status"] == "rolled-back":
        return EXIT_ROLLED_BACK
    return 0


if __name__ == "__main__":
    sys.exit(main())
