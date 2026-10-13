#!/usr/bin/env python3
"""
Build every GrizzDog-AI lab model in Ollama (all 4 personas x 4 hardening
tiers, plus vulnerable_bot / hardened_bot fallbacks) in one command.

Pulls the base model named in the Modelfiles' FROM line if it is missing,
then runs `ollama create` for each model. Safe to re-run: it rebuilds from
the current Modelfiles, which is also how you apply edits to them.

Usage (from the repo root):
    python lab/scripts/build_models.py            # native Ollama (Windows/Mac/Linux)
    python lab/scripts/build_models.py --docker   # Ollama in the Docker `llm` container
    python lab/scripts/build_models.py --check    # only report which models are missing
    python lab/scripts/build_models.py --only ta grader   # just these personas
    python lab/scripts/build_models.py --no-pull  # never download the base model

Exit code is 0 only if every requested model exists afterwards.
"""

import argparse
import os
import re
import subprocess
import sys

MODELFILE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "modelfiles"))
DOCKER_MODELFILE_DIR = "/app/lab/modelfiles"  # repo is mounted at /app in docker-compose.yml

PERSONAS = ["grizzdog", "ta", "grader", "registrar"]
TIERS = ["vulnerable", "basic", "hardened", "paranoid"]
# Fallbacks the gateway uses when a persona model is missing.
EXTRA_MODELS = {"vulnerable_bot": "vulnerable.txt", "hardened_bot": "hardened.txt"}


def lab_models(only=None):
    """[(model_name, modelfile_name)] in build order."""
    models = [
        (f"{p}_{t}", f"{p}_{t}.txt")
        for p in PERSONAS if not only or p in only
        for t in TIERS
    ]
    if not only or "bots" in only:
        models += list(EXTRA_MODELS.items())
    return models


def ollama_cmd(docker, *args):
    prefix = ["docker", "compose", "exec", "-T", "llm"] if docker else []
    return prefix + ["ollama", *args]


def run(cmd, capture=False):
    try:
        return subprocess.run(cmd, check=False, text=True, encoding="utf-8", errors="replace",
                              capture_output=capture)
    except FileNotFoundError:
        tool = "docker" if cmd[0] == "docker" else "ollama"
        sys.exit(f"ERROR: '{tool}' was not found on PATH. "
                 + ("Is Docker Desktop running?" if tool == "docker"
                    else "Install Ollama from https://ollama.com/download (or use --docker)."))


def installed_models(docker):
    res = run(ollama_cmd(docker, "list"), capture=True)
    if res.returncode != 0:
        sys.exit("ERROR: could not reach Ollama.\n" + (res.stderr or res.stdout).strip()
                 + ("\nIs the stack up? Try: docker compose up -d" if docker
                    else "\nIs Ollama running? Start it from the system tray or run: ollama serve"))
    names = set()
    for line in res.stdout.splitlines()[1:]:
        if line.strip():
            full = line.split()[0]
            names.add(full)
            if full.endswith(":latest"):
                names.add(full[: -len(":latest")])
    return names


def base_models(models):
    bases = set()
    for _name, fname in models:
        with open(os.path.join(MODELFILE_DIR, fname), "r", encoding="utf-8") as f:
            m = re.search(r"^\s*FROM\s+(\S+)", f.read(), re.MULTILINE | re.IGNORECASE)
        if m:
            bases.add(m.group(1))
    return sorted(bases)


def main():
    ap = argparse.ArgumentParser(description="Build all GrizzDog-AI lab models in Ollama.")
    ap.add_argument("--docker", action="store_true", help="run ollama inside the docker compose `llm` service")
    ap.add_argument("--check", action="store_true", help="only report missing models; change nothing")
    ap.add_argument("--only", nargs="+", choices=PERSONAS + ["bots"], help="limit to these personas")
    ap.add_argument("--no-pull", action="store_true",
                    help="never download the base model; fail if it is missing (used by the auto-updater)")
    args = ap.parse_args()

    models = lab_models(args.only)
    missing_files = [f for _n, f in models if not os.path.exists(os.path.join(MODELFILE_DIR, f))]
    if missing_files:
        sys.exit(f"ERROR: missing Modelfiles in {MODELFILE_DIR}: {', '.join(missing_files)}")

    have = installed_models(args.docker)
    missing = [n for n, _f in models if n not in have]

    if args.check:
        print(f"{len(models) - len(missing)}/{len(models)} lab models present.")
        for n in missing:
            print(f"  MISSING  {n}")
        if missing:
            print("Build them with: python lab/scripts/build_models.py" + (" --docker" if args.docker else ""))
        return 1 if missing else 0

    for base in base_models(models):
        if base not in have:
            if args.no_pull:
                sys.exit(f"ERROR: base model {base} is not installed and --no-pull was given.")
            print(f"==> Pulling base model {base} (one-time download)...")
            if run(ollama_cmd(args.docker, "pull", base)).returncode != 0:
                sys.exit(f"ERROR: failed to pull {base}")

    mf_dir = DOCKER_MODELFILE_DIR if args.docker else MODELFILE_DIR
    failed = []
    for i, (name, fname) in enumerate(models, 1):
        print(f"==> [{i}/{len(models)}] {name}")
        res = run(ollama_cmd(args.docker, "create", name, "-f", f"{mf_dir}/{fname}"), capture=True)
        if res.returncode != 0:
            failed.append(name)
            err = (res.stderr or res.stdout).strip()
            print(f"    FAILED: {err.splitlines()[-1] if err else 'unknown error'}")

    print()
    if failed:
        print(f"{len(models) - len(failed)}/{len(models)} built. Failed: {', '.join(failed)}")
        return 1
    print(f"All {len(models)} lab models built.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
