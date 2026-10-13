# GrizzDog-AI — Docker Compose + Ollama Setup Guide
## Butler Community College (Andover Campus) Cyber Faculty Research Project

> [!IMPORTANT]
> **Academic Notice & Educational Disclaimer**:
> **GrizzDog-AI is an independent academic research and pedagogical cybersecurity lab developed by a Butler Community College Cyber Defense faculty member. It is NOT an official Butler Community College institutional project, endorsement, or service.**
> This lab environment is strictly intended for educational research, student exercises, and defensive security testing within accredited curricula (aligned with Butler's NSA/DHS CAE-CD designated program).
>
> **Upstream Attribution**: GrizzDog-AI is adapted from the foundational cybersecurity architecture created by **[SixFiveMil](https://github.com/SixFiveMil)** in **[Securing-AI](https://github.com/SixFiveMil/Securing-AI)**. Full credit is given to SixFiveMil for the pioneering defense-in-depth concepts and benchmark designs.

Companion setup guide for the **GrizzDog-AI Cyber Defense Lab** suite.  
Repo: `https://github.com/daTechGuy/GrizzDog-AI`  
Affiliation: **Butler Community College Cyber Defense Faculty Project (Andover, KS)**

Everything runs **locally** — no cloud account, no external API key, and no per-token billing. Total one-time setup, including the base model download, takes ~15–20 minutes on a typical broadband connection.

---

## At a Glance

- **Goal:** Run the local AI security lab end-to-end with Docker, Ollama, the Butler Grizzly / GrizzDog Purple & Gold gateway, and OPA policy checks.
- **Main Interface:** `http://localhost:5000` (Butler Grizzly Cyber Defense Web Gateway & Benchmark Suite)
- **Core Services:** `llm` (Ollama), `web` (Flask Gateway), and `opa` (Open Policy Agent)
- **Duration:** ~15–20 minutes for first-time setup
- **Dependencies:** Docker Desktop, internet access for initial model pull, and 8GB+ RAM

---

## Quick Reference Card

```bash
# 1. Start the Docker stack from the repo root
docker compose up -d

# 2. Pull the lightweight base model into Ollama (one time, ~2GB)
docker compose exec llm ollama pull llama3.2

# Build all 18 lab models (4 personas x 4 hardening tiers + 2 fallback bots).
# Re-run any time you edit a Modelfile. Add --check to just list missing models.
python lab/scripts/build_models.py --docker

# 4. Open the GrizzDog Gateway in your browser:
#    http://localhost:5000

# 5. Evaluate Blue Team rules anytime (no Docker needed):
python lab/scripts/evaluate_rules.py --verbose

# 6. Switch difficulty tiers during lecture or demo:
python lab/scripts/set_tier.py [blank|scaffolded|calibrated]
```

---

## Before You Start

### Prerequisites

- **Docker Desktop** installed and running ([docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop))
- **~5GB free disk space** (model weights + container images)
- **8GB+ RAM recommended** to run a 3B-parameter model comfortably
- **Internet access** for the one-time model pull — after that, everything runs offline
- **Git** (or download as ZIP from GitHub)

No local Python install is required if running via Docker; the gateway runs inside the `web` container. If running without Docker, Python 3.10+ is supported.

### OS Readiness

#### Windows

##### Option A: Docker Desktop (WSL 2)
- Docker Desktop requires hardware virtualization.
- Ensure **Virtualization Technology** (Intel VT-x or AMD-V) is enabled in BIOS/UEFI.
- If using WSL2, open PowerShell as Administrator and run:
  ```powershell
  wsl --install
  ```
- Restart your computer and ensure **Use the WSL 2 based engine** is checked in Docker Desktop Settings.

##### Option B: Native Windows Setup (Fastest — No Docker, WSL, or Hyper-V Required)
If you do not have WSL installed or prefer running directly on Windows with native GPU acceleration:
1. **Install Ollama for Windows**: Download and run the installer from [ollama.com/download/windows](https://ollama.com/download/windows). Ollama runs in your system tray at `http://localhost:11434`.
2. **Pull the base model**:
   ```powershell
   ollama pull llama3.2
   ```
3. **Build the lab personas**:
   ```powershell
   # Build all 18 lab models (4 personas x 4 hardening tiers + 2 fallback bots).
   # Re-run any time you edit a Modelfile. Add --check to just list missing models.
   python lab/scripts/build_models.py
   ```
4. **Install Python dependencies & run gateway**:
   ```powershell
   pip install -r requirements.txt
   python lab/scripts/secure_gateway.py
   ```
   Open `http://localhost:5000` in your browser.

#### macOS (Apple Silicon M1/M2/M3/M4 & Intel)

macOS requires specific configuration to avoid known port conflicts, missing CLI paths, and VM memory exhaustion:

##### 0. Fix "docker: command not found" after Installation — CRITICAL
If you just installed Docker Desktop and it is running, but Terminal says `docker: command not found`, Docker Desktop has not symlinked the CLI tools into your system `$PATH` yet:

- **Method A (Easiest via Docker Settings)**:
  1. Open **Docker Desktop**.
  2. Click the **Settings (gear icon)** in the top-right corner.
  3. Go to **Advanced**.
  4. Under **Choose how to install Docker CLI tools**, select **System (requires password)**.
  5. Click **Apply & restart** and enter your macOS administrator password when prompted.
  6. **Restart your Terminal app** (quit with `Cmd + Q` and reopen).

- **Method B (Quick 1-Line Terminal Fix)**:
  Run this command in Terminal to create the symlinks directly:
  ```bash
  sudo ln -sf /Applications/Docker.app/Contents/Resources/bin/docker /usr/local/bin/docker
  sudo ln -sf /Applications/Docker.app/Contents/Resources/bin/docker-compose /usr/local/bin/docker-compose
  ```
  Or if Docker put tools in `~/.docker/bin`, add it to your shell:
  ```bash
  echo 'export PATH="$HOME/.docker/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
  ```

- **Verify in Terminal**:
  ```bash
  docker --version
  docker compose version
  ```

##### 1. Disable AirPlay Receiver (Port 5000 Conflict) — CRITICAL
By default, macOS Monterey (12.x), Ventura (13.x), Sonoma (14.x), and Sequoia (15.x) run Apple's **AirPlay Receiver** system service on port **5000**. If left enabled, Docker will fail with `bind: address already in use: 5000` or the browser will return a 403 Forbidden.
- **Fix (Recommended)**: Open **System Settings > General > AirDrop & AirPlay**.
- Toggle **AirPlay Receiver** to **OFF**.
- *Alternative*: If you need AirPlay enabled, set an alternate port when starting Docker:
  ```bash
  WEB_PORT=5001 docker compose up -d
  # Then open http://localhost:5001 in your browser
  ```

##### 2. Allocate Docker Desktop VM RAM (Prevents Crashes & Freezes) — CRITICAL
Docker Desktop on Mac runs a lightweight Linux VM. By default, it allocates only **2 GB or 4 GB of RAM**, which is **insufficient** for LLM inference (Llama 3.2 requires ~3 GB alone). When memory runs out, the Linux kernel terminates Ollama (`killed` / exit code 137) or freezes Docker Desktop completely:
1. Open **Docker Desktop Settings** (gear icon in top right).
2. Go to **Resources** (or **Resources > Advanced**).
3. Increase **Memory** to at least **8 GB** (minimum 6 GB).
4. Increase **CPUs** to at least **4 cores**.
5. Set **Swap** to at least **2 GB**.
6. Click **Apply & restart**.

##### 3. Check for Existing Native Ollama (Port 11434 Conflict)
If you already installed the native Ollama Mac app (`brew install ollama` or from ollama.com), it may be running in the menu bar and holding port **11434**, preventing the Docker `llm` container from binding to that port:
- Check for the llama icon in the top macOS menu bar and click **Quit Ollama**, or run:
  ```bash
  pkill ollama
  ```

##### 4. Apple Silicon Performance Settings
In **Docker Desktop Settings**:
- **General**: Ensure **Use Virtualization framework** is checked.
- **Resources > File sharing**: Select **VirtioFS** (provides fastest file sync).
- **Features in development**: Enable **Use Rosetta for x86/amd64 emulation on Apple Silicon**.

##### 5. Alternative Track: Native macOS Setup (Fastest on Apple Silicon)
On M-series Macs (M1/M2/M3/M4), running Ollama natively on macOS leverages **Apple Metal GPU acceleration** directly on unified memory (up to 10x faster inference than running inside a Docker VM):
```bash
# 1. Install Ollama natively on Mac:
brew install ollama   # or download from https://ollama.com/download/mac
ollama serve &
ollama pull llama3.2

# Build all 18 lab models (4 personas x 4 hardening tiers + 2 fallback bots).
# Re-run any time you edit a Modelfile. Add --check to just list missing models.
python lab/scripts/build_models.py

# 3. Run the gateway directly on your Mac:
pip3 install -r requirements.txt
python3 lab/scripts/secure_gateway.py
# Open http://localhost:5000 (or http://localhost:5001 if AirPlay is on)
```

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/daTechGuy/GrizzDog-AI.git
cd GrizzDog-AI
```

### Repo Contents

| File / Folder | Purpose |
|---|---|
| `README.md` | Architecture overview, lab missions, and quickstart |
| `docker-compose.yml` | Starts `llm` (Ollama), `web` (gateway), and `opa` (policy engine) |
| `requirements.txt` | Python dependencies installed automatically inside `web` container |
| `lab/modelfiles/` | Modelfiles for GrizzDog (Quadruped Sentry), Sage (TA), GraderBot, and Morgan across 4 hardening tiers |
| `lab/scripts/secure_gateway.py` | GrizzDog Cyber-Purple browser gateway with in-UI system prompt editor & benchmark |
| `lab/scripts/filter_rules.py` | Active Blue Team edit surface for ingress and egress filtering |
| `lab/scripts/evaluate_rules.py` | Standalone CLI grader scoring security vs benign usability |
| `lab/scripts/set_tier.py` | Live difficulty tier switcher (`blank`, `scaffolded`, `calibrated`) |
| `lab/scripts/build_models.py` | Builds all 18 Ollama lab models (`--docker`, `--check`, `--only`) |
| `lab/scripts/benchmark.py` | Shared visible + held-out benchmark used by the web UI and `evaluate_rules.py` |
| `lab/scripts/verify_report.py` | Instructor check of signed Canvas reports (needs `REPORT_SECRET`) |
| `lab/scripts/make_qr.py` | Regenerates the booth QR code SVG in `lab/assets/` |
| `policies/rules.json` | OPA policy thresholds, academic domains, intents, and risk flags |
| `policies/gateway.rego` | Rego decision logic executed by Open Policy Agent |
| `docs/assignments/` | Student Red/Blue team guides, Instructor Guide (100-pt rubric), and defense briefs |

---

## Step 2 — Start the Docker Stack

```bash
docker compose up -d
```

Verify all three containers are healthy:

```bash
docker ps
```

You should see:
- `llm` on port `11434`
- `opa` on port `8181`
- `web` on port `5000`

---

## Step 3 — Pull the Base Model

All Modelfiles build on `FROM llama3.2`, so pull the base model into the `llm` container:

```bash
docker compose exec llm ollama pull llama3.2
```

This is a **one-time ~2GB download**. Instructors should pull this before class.

---

## Step 4 — Build the Educational Lab Models

Build every persona (GrizzDog, Sage the TA, GraderBot, Morgan the Registrar) across the **4 Progressive Hardening Tiers** (Vulnerable → Basic → Hardened → Paranoid) with one script. It pulls the base model if needed and runs `ollama create` for each Modelfile:

```bash
# Build all 18 lab models (4 personas x 4 hardening tiers + 2 fallback bots).
# Re-run any time you edit a Modelfile. Add --check to just list missing models.
python lab/scripts/build_models.py --docker
```

Verify installed models:

```bash
docker compose exec llm ollama list
```

---

## Step 5 — Open the GrizzDog Defense Gateway

Open in any browser:

```text
http://localhost:5000
```

### Gateway Interface Features

1. **Cyber-Purple HUD**: Live quadruped telemetry indicators (`GRIZZDOG PATROL: ONLINE`, `LIDAR: 360° ARMED`, `NEURAL GUARDRAIL: LEVEL 4 PURPLE`).
2. **Unit Persona Selector**:
   - 🐕 **GrizzDog** (Autonomous Quadruped Sentry)
   - 🎓 **Sage** (Course TA Bot - CS101/Cyber)
   - 📝 **GraderBot** (Canvas LMS Auto-Grader)
   - 🏛️ **Morgan** (Registrar & Admissions Advisor)
3. **Hardening Level (4 Tiers)**:
   - `Level 1: Ultra-Vulnerable (Naive)` — Zero resistance, easy first-win prompt extraction.
   - `Level 2: Basic` — Standard defensive prompt, vulnerable to roleplay and authority spoofing.
   - `Level 3: Hardened` — Strict role boundaries, refusal of authority claims, Socratic tutoring limit.
   - `Level 4: Paranoid (Zero-Trust)` — Rigid output templates, immediate access violation rejection.
4. **Defense Architecture**:
   - **Phase 1: Direct Neural Model** (No gateway filtering)
   - **Phase 2: Static Filters** (Ingress blacklist & egress DLP in `filter_rules.py`)
   - **Phase 3: OPA Policy Enforcement** (Intent classification & context rules in `rules.json`)
5. **🛡️ 3-Phase Defense Architecture Studio (In-Browser Tuning)**:
   - **🟣 Phase 1 Tab (`modelfiles/*.txt`)**: Edit active system instructions for any persona and tier. Click **Save & Apply** for instant hot-reload, or **Rebuild in Ollama Runtime** to compile.
   - **🟡 Phase 2 Tab (`filter_rules.py`)**: Edit Python perimeter rules (`INGRESS_BLACKLIST`, `EGRESS_SECRETS`, `EGRESS_PATTERNS`). Features automated Python syntax checking before saving, plus one-click presets (*Calibrated 100%*, *Scaffolded Starter*, *Blank*).
   - **🔵 Phase 3 Tab (`rules.json`)**: Edit Open Policy Agent policy rules, intent taxonomies, confidence thresholds, and risk flags with live JSON linting, formatting, and file-watcher hot-reloads.
   - **Visual Phase Switching**: Prominent color-coded tabs with auto-sync to the *Defense Architecture* selector.
6. **📊 Automated Defense Benchmark**: Click **Run Butler Grizzly Benchmark** in the browser for an instant scorecard (visible tests plus a held-out generalization score).

---

## Step 6 — Blue Team Defense Engineering

### Option A — In-Browser Defense Studio (Recommended)
You can engineer defenses directly in the web browser at `http://localhost:5000`:
1. Select the defense phase you want to edit:
   - **🟣 Phase 1**: Model System Instructions
   - **🟡 Phase 2**: Static Ingress/Egress Rules (`filter_rules.py`)
   - **🔵 Phase 3**: OPA Context Policy (`rules.json`)
2. Make your edits inside the code editor (press `Tab` to indent).
3. Click **Save & Hot-Reload** — the gateway validates your Python or JSON syntax before saving and immediately activates your rules.
4. Test immediately using the quick-attack mission links or click **Run Butler Grizzly Benchmark**.

### Option B — Terminal & File Editing
You can also edit files in your favorite editor:
- [`lab/scripts/filter_rules.py`](filter_rules.py): Ingress blacklist and egress DLP secrets/patterns.
- [`policies/rules.json`](../policies/rules.json): OPA declarative policy configuration.
- [`lab/modelfiles/`](../lab/modelfiles/): Neural model prompts.

The gateway **hot-reloads `filter_rules.py` and `rules.json` on every request**, requiring no container restarts.

### Running the Evaluator
Test defense efficacy from your terminal:

```bash
python lab/scripts/evaluate_rules.py --verbose
```

Scoring formula:
$$\text{Composite Score} = (0.60 \times \text{Attack Catch Rate}) + (0.40 \times \text{Benign Usability Rate})$$

---

## Updating Existing Installs to the Latest Version

If you already set up the lab previously and want to update to the latest features (new GrizzDog hardening tiers, in-browser 3-phase defense studio, Butler CC theming):

### 1. Update Repository Code
```bash
git pull origin main
```
*(If you have uncommitted local file modifications you wish to overwrite: `git fetch origin && git reset --hard origin/main`)*

### 2. Restart or Recreate Docker Containers
```bash
# Quick restart:
docker compose restart web

# Or complete rebuild:
docker compose down
docker compose up -d --build
```

### 3. Rebuild Models in Ollama
```bash
# Build all 18 lab models (4 personas x 4 hardening tiers + 2 fallback bots).
# Re-run any time you edit a Modelfile. Add --check to just list missing models.
python lab/scripts/build_models.py --docker
```

### 4. Updating Docker to the Latest Version
If your Docker Desktop is outdated:
- **Mac & Windows GUI**: Open Docker Desktop > ⚙️ Settings > **Software Updates** > **Check for updates** > **Download and install**.
- **Windows (Terminal)**: `winget upgrade Docker.DockerDesktop`
- **Mac (Terminal / Homebrew)**: `brew upgrade --cask docker`
- **Linux**: `sudo apt-get update && sudo apt-get --only-upgrade install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin`

---

## Automatic Updates (Launcher)

Start the lab with the launcher instead of running the scripts by hand:

| | Windows | Mac / Linux |
| :--- | :--- | :--- |
| Native | `.\start.bat` | `./start.sh` |
| Docker | `.\start.bat --docker` | `./start.sh --docker` |
| Booth laptop | `.\start.bat --kiosk` | `./start.sh --kiosk` |

*(Type `.\start.bat` with the leading `.\`; PowerShell requires it, and some Windows setups won't find `start.bat` in the current folder without it.)*

It updates to the newest **release tag** first, then starts. Full behavior: README, *Automatic Updates & Releases*.

**Setting up a laptop so it follows releases:** clone the repo normally (`git clone https://github.com/daTechGuy/GrizzDog-AI.git`). It will move forward to each new release at launch. To start exactly on a release instead of the latest commit: `git checkout v1.1.0` after cloning. (Detached on a tag is fine; the launcher moves it to newer tags.)

**Before an event:**
1. Launch once at home with internet, so updates and any model rebuilds finish before you travel.
2. Run `.\start.bat --check` to confirm "Up to date (vX.Y.Z)".
3. Freeze it: set `GRIZZDOG_NO_UPDATE=1` (PowerShell: `$env:GRIZZDOG_NO_UPDATE="1"`), or launch with `--no-update`.
4. At the venue, launch with `--no-update --kiosk` (no Wi-Fi needed).

**Releasing (instructor):** `git tag -a v1.1.0 -m "what changed"` then `git push origin v1.1.0`. Laptops pick it up at their next launch. To fix a bad release, publish a fixed, newer tag (e.g. `v1.1.1`); laptops move forward to it at their next launch. Deleting a tag on GitHub does not remove it from laptops that already fetched it. A laptop that took a bad release can be put back by hand with `git checkout <older tag>`.

**Student work during updates:** your edits to `filter_rules.py`, `rules.json` and the Modelfiles are preserved automatically (backups in `.grizzdog/backups/`, last 5 kept). To go back to the shipped default for one file: `git checkout -- lab/scripts/filter_rules.py`.

---

## Booth Laptop Lockdown Checklist

The gateway has no login. For public events, lock it down in layers:

1. **Kiosk mode + local-only (the default binding).** Simplest: `.\start.bat --kiosk` (or `--docker --kiosk`); it also updates first unless you add `--no-update`. By hand:
   ```bash
   # Docker
   GRIZZDOG_KIOSK=1 docker compose up -d
   # Native PowerShell
   $env:GRIZZDOG_KIOSK="1"; python lab/scripts/secure_gateway.py
   ```
   *(Note: Legacy `EDUGUARD_KIOSK=1` is also supported for backwards compatibility).*
   The console prints `Booth kiosk mode` on start. The header shows **🔒 BOOTH KIOSK** and there is no Classroom Studio switch.
2. **Full-screen browser** so visitors can't open other tabs, dev tools or files:
   - Edge: `msedge --kiosk http://localhost:5000 --edge-kiosk-type=fullscreen`
   - Chrome: `chrome --kiosk http://localhost:5000`
   Exit with `Alt+F4`.
3. **Separate Windows account** for the booth (no admin rights, no saved passwords), or Windows *Assigned Access* to run only the browser.
4. **Firewall:** block inbound TCP 5000, 11434 and 8181 (`New-NetFirewallRule -DisplayName "GrizzDog block inbound" -Direction Inbound -Protocol TCP -LocalPort 5000,11434,8181 -Action Block`).
5. **Network:** prefer a private hotspot or no network at all. The offline simulator keeps all three booth stages playable without Wi-Fi.
6. **Before you leave:** close the browser, stop the stack (`docker compose down`) and sign out of the booth account.

### Live Ollama AI vs. Offline Heuristic Simulation

A common question when preparing a booth laptop is whether Kiosk Mode requires Ollama to be running:

* **When Ollama is running (`http://localhost:11434`)**: Kiosk Mode executes live local AI inference against the custom `grizzdog` models. The pipeline trace displays `EXECUTED ✓` on Node 4.
* **When Ollama is offline or not installed**: The gateway automatically falls back to the built-in deterministic simulator (`SIMULATED ⚠️`). The entire 3-stage "Beat the GrizzDog" challenge remains fully functional, leaking real target secrets and honoring Phase 2 & Phase 3 defenses, with zero latency and zero dependency on a GPU or internet connection.

---

## Troubleshooting

| Problem | Likely Cause / Solution |
|---|---|
| **Mac**: `docker: command not found` | Docker CLI tools are not symlinked in your PATH. In **Docker Desktop > Settings > Advanced**, select **System (requires password)** and click **Apply & restart**, or run `sudo ln -sf /Applications/Docker.app/Contents/Resources/bin/docker /usr/local/bin/docker`. Restart Terminal. |
| **Mac**: Port 5000 `address already in use` | macOS **AirPlay Receiver** binds to port 5000. Turn it off in **System Settings > General > AirDrop & AirPlay > AirPlay Receiver (OFF)**, or run `WEB_PORT=5001 docker compose up -d`. |
| **Mac**: Port 11434 `address already in use` | Native Ollama Mac app is running in the menu bar. Run `pkill ollama` in Terminal or quit Ollama from the menu bar. |
| **Mac**: Container killed (`exit 137`) / Docker hangs / freeze | Docker VM ran out of memory (OOM). Allocate at least **8 GB RAM** in **Docker Desktop Settings > Resources**. |
| **Mac**: Slow inference inside Docker | Docker VM runs Ollama on CPU. Use the **Native macOS Setup** track in Step 1 to leverage Apple Silicon Metal GPU acceleration directly. |
| Browser at `localhost:5000` won't load | Allow 10–15 seconds on initial start for `requirements.txt` installation. Check `docker compose logs web`. |
| Gateway returns error contacting model | Confirm `docker compose exec llm ollama list` shows `vulnerable_bot` or `llama3.2`. |
| Model pull is slow or times out | Campus firewall or slow Wi-Fi. Pre-pull on home connection or mobile hotspot. |
| Modified system prompt not showing | Click **Save & Apply** in the UI editor or refresh the page. |
| OPA policy blocks unexpected queries | Review `policies/rules.json` confidence thresholds and ensure allowed intents cover your query. |
| Phase 3 node says "Local Policy Evaluator (OPA engine offline)" | Normal on native Windows/Mac setups: the gateway evaluates `rules.json` with a Python port of `gateway.rego`, so your edits still apply. If it also says "classifier offline", Ollama isn't reachable and only the `rules.json` blacklist is checked. To use real OPA natively, run `opa run --server --watch .` inside `policies/` and start the gateway with `OPA_ENABLED=true OPA_URL=http://localhost:8181/v1/data/gateway/decision`. |
| Launcher says "Update ... skipped: uncommitted changes in ..." | A tracked file other than the student-editable rules/prompts has local edits (`git status` shows which). Commit or discard them (`git checkout -- <file>`), then start again. |
| "failed its self-check ... staying on vX" | The newest release didn't pass the automatic start-up test on this computer and was rolled back. Nothing is lost. It is retried when a newer release is published; to retry now, delete `.grizzdog/update_state.json`. |
| "Could not reach GitHub (offline?)" | Normal without internet: the launcher starts the version you already have. |
| `start.bat` is "not recognized" | Type `.\start.bat` (with `.\`) or double-click it from File Explorer. |
| `Host '...' not allowed` (403) | The gateway only answers to `localhost` / `127.0.0.1` by default. Browse to `http://localhost:5000`, or for a LAN classroom server set `GRIZZDOG_ALLOWED_HOSTS` (or `EDUGUARD_ALLOWED_HOSTS`) (e.g. `*` or the server's IP). |
| Other computers can't open the gateway | By design: it listens on this computer only. See the README's *Security & Network Lockdown* section to opt in to LAN access. |
| `filter_rules.py` save rejected ("only ... lists are allowed") | The file is data, not code: keep only the three `NAME = ["...", ...]` lists (comments are fine). |
| Every Phase 3 request blocked with "OPA unavailable" (Docker) | Check `docker compose logs opa`. OPA loads every `.json` in `policies/` into one data tree, so keep extra copies of `rules.json` (backups, presets) **outside** that folder or OPA will refuse to start with a merge error. |
| Docker daemon not running | Ensure Docker Desktop is launched and running in the system tray before running commands. |

---

## Cleanup & Fresh Reset

To remove all lab containers and start fresh:

```bash
docker compose down -v
```

To remove custom models from Ollama storage:
```bash
docker compose exec llm ollama rm grizzdog_vulnerable
docker compose exec llm ollama rm grizzdog_basic
docker compose exec llm ollama rm grizzdog_hardened
docker compose exec llm ollama rm grizzdog_paranoid
docker compose exec llm ollama rm vulnerable_bot
docker compose exec llm ollama rm hardened_bot
docker compose exec llm ollama rm grader_vulnerable
docker compose exec llm ollama rm grader_hardened
docker compose exec llm ollama rm registrar_vulnerable
docker compose exec llm ollama rm registrar_hardened
docker compose exec llm ollama rm unitree_vulnerable
docker compose exec llm ollama rm unitree_hardened
```

---

## Acknowledgments & Upstream Lineage

GrizzDog-AI was adapted from the foundational architecture designed by **[SixFiveMil](https://github.com/SixFiveMil)** in the project **[Securing-AI](https://github.com/SixFiveMil/Securing-AI)**. We gratefully acknowledge SixFiveMil's original work on multi-layered LLM defense pipelines and educational benchmark frameworks.