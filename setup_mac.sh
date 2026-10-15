#!/usr/bin/env bash
# ==============================================================================
# GrizzDog-AI — One-Line Turnkey Installer for macOS (Apple Silicon & Intel)
# Butler Community College Cyber Faculty Research Project (Andover Campus)
# ==============================================================================
# Usage:
#   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/daTechGuy/GrizzDog-AI/main/setup_mac.sh)"
# Or locally:
#   ./setup_mac.sh
# ==============================================================================

set -e

# ANSI Color formatting (Butler Purple & Gold)
CLR_RESET="\033[0m"
CLR_PURPLE="\033[1;35m"
CLR_GOLD="\033[1;33m"
CLR_CYAN="\033[1;36m"
CLR_GREEN="\033[1;32m"
CLR_RED="\033[1;31m"

echo -e "${CLR_PURPLE}"
cat << 'EOF'
   ____       _              ____                    _    ___ 
  / ___|_ __ (_)___________ |  _ \  ___   __ _      / \  |_ _|
 | |  _| '__|| |_  /_  / _ \| | | |/ _ \ / _` |    / _ \  | | 
 | |_| | |   | |/ / / / (_) | |_| | (_) | (_| |   / ___ \ | | 
  \____|_|   |_/___/___\___/|____/ \___/ \__, |  /_/   \_\___|
                                         |___/                
  Butler Community College — Cyber Defense Lab & Guardrail Sandbox
EOF
echo -e "${CLR_GOLD}Turnkey Installer for macOS (Apple Silicon M1-M4 & Intel)${CLR_RESET}"
echo "------------------------------------------------------------------"

# Step 1: Verify Operating System
OS_NAME="$(uname -s)"
if [ "$OS_NAME" != "Darwin" ]; then
    echo -e "${CLR_RED}[error] This script is optimized for macOS. Detected: ${OS_NAME}.${CLR_RESET}"
    echo "For Linux/Windows, please follow the instructions in lab/SETUP_GUIDE.md."
    exit 1
fi

ARCH="$(uname -m)"
echo -e "${CLR_CYAN}[1/7] Detected macOS on ${ARCH} architecture.${CLR_RESET}"

# Step 2: Ensure Homebrew is installed and configured on PATH
BREW_BIN=""
if command -v brew >/dev/null 2>&1; then
    BREW_BIN="$(command -v brew)"
elif [ -x "/opt/homebrew/bin/brew" ]; then
    BREW_BIN="/opt/homebrew/bin/brew"
elif [ -x "/usr/local/bin/brew" ]; then
    BREW_BIN="/usr/local/bin/brew"
fi

if [ -z "$BREW_BIN" ]; then
    echo -e "${CLR_GOLD}[2/7] Homebrew not found. Installing Homebrew & Apple Developer Tools...${CLR_RESET}"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    
    if [ -x "/opt/homebrew/bin/brew" ]; then
        BREW_BIN="/opt/homebrew/bin/brew"
    elif [ -x "/usr/local/bin/brew" ]; then
        BREW_BIN="/usr/local/bin/brew"
    fi
    
    if [ -n "$BREW_BIN" ]; then
        SHELL_PROFILE="$HOME/.zprofile"
        if [ ! -f "$SHELL_PROFILE" ] || ! grep -q "brew shellenv" "$SHELL_PROFILE"; then
            echo "" >> "$SHELL_PROFILE"
            echo "eval \"\$($BREW_BIN shellenv)\"" >> "$SHELL_PROFILE"
        fi
        eval "$($BREW_BIN shellenv)"
    fi
else
    echo -e "${CLR_GREEN}[2/7] Homebrew found at ${BREW_BIN}.${CLR_RESET}"
    eval "$($BREW_BIN shellenv 2>/dev/null || true)"
fi

# Step 3: Install Core Prerequisites via Homebrew
echo -e "${CLR_CYAN}[3/7] Verifying dependencies (python, git, ollama)...${CLR_RESET}"
DEPS_TO_INSTALL=()
command -v python3 >/dev/null 2>&1 || DEPS_TO_INSTALL+=("python")
command -v git >/dev/null 2>&1 || DEPS_TO_INSTALL+=("git")
command -v ollama >/dev/null 2>&1 || DEPS_TO_INSTALL+=("ollama")

if [ ${#DEPS_TO_INSTALL[@]} -gt 0 ]; then
    echo "Installing missing packages via Homebrew: ${DEPS_TO_INSTALL[*]}"
    brew install "${DEPS_TO_INSTALL[@]}"
else
    echo -e "${CLR_GREEN}All system dependencies (python, git, ollama) are installed.${CLR_RESET}"
fi

# Step 4: Clone or Verify GrizzDog-AI Repository
TARGET_DIR=""
if [ -f "lab/scripts/secure_gateway.py" ]; then
    TARGET_DIR="$(pwd)"
    echo -e "${CLR_GREEN}[4/7] Running inside repository: ${TARGET_DIR}${CLR_RESET}"
else
    TARGET_DIR="$HOME/GrizzDog-AI"
    echo -e "${CLR_CYAN}[4/7] Setting up repository at ${TARGET_DIR}...${CLR_RESET}"
    if [ -d "$TARGET_DIR/.git" ]; then
        echo "Existing repository detected. Fetching latest updates..."
        git -C "$TARGET_DIR" pull --ff-only || true
    else
        git clone https://github.com/daTechGuy/GrizzDog-AI.git "$TARGET_DIR"
    fi
    cd "$TARGET_DIR"
fi

# Step 5: Setup Python Virtual Environment (.venv) & Install Requirements
echo -e "${CLR_CYAN}[5/7] Preparing Python virtual environment (.venv)...${CLR_RESET}"
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

.venv/bin/pip install --upgrade pip --quiet
.venv/bin/pip install -r requirements.txt --quiet
echo -e "${CLR_GREEN}Python dependencies installed successfully.${CLR_RESET}"

# Step 6: Start Ollama Service and Pull Base Model
echo -e "${CLR_CYAN}[6/7] Checking Ollama service and llama3.2 base model...${CLR_RESET}"
# Check if Ollama is running
OLLAMA_RUNNING=0
if curl -s -f http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    OLLAMA_RUNNING=1
fi

if [ $OLLAMA_RUNNING -eq 0 ]; then
    echo "Starting Ollama service via brew services..."
    brew services start ollama >/dev/null 2>&1 || true
    # Wait up to 15 seconds for Ollama daemon to initialize
    for i in {1..15}; do
        if curl -s -f http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
            OLLAMA_RUNNING=1
            break
        fi
        sleep 1
    done
fi

if [ $OLLAMA_RUNNING -eq 1 ]; then
    echo -e "${CLR_GREEN}Ollama is online.${CLR_RESET}"
    # Check if llama3.2 is already downloaded
    if ! ollama list 2>/dev/null | grep -q "llama3.2"; then
        echo -e "${CLR_GOLD}Downloading base model 'llama3.2' (~2GB)...${CLR_RESET}"
        ollama pull llama3.2
    else
        echo -e "${CLR_GREEN}Base model 'llama3.2' already present.${CLR_RESET}"
    fi
else
    echo -e "${CLR_GOLD}[warn] Ollama background service did not respond in time.${CLR_RESET}"
    echo "The lab will still run in offline simulation mode, or you can start Ollama manually with: ollama serve"
fi

# Step 7: Build the 18 Lab Models
echo -e "${CLR_CYAN}[7/7] Verifying and building 18 educational lab models...${CLR_RESET}"
if [ $OLLAMA_RUNNING -eq 1 ]; then
    .venv/bin/python lab/scripts/build_models.py
else
    echo "Skipping model compile for now since Ollama is offline. Re-run anytime with:"
    echo "  .venv/bin/python lab/scripts/build_models.py"
fi

# AirPlay Port 5000 Conflict Detection
PORT_INFO="http://localhost:5000"
if lsof -i :5000 >/dev/null 2>&1; then
    PORT_INFO="http://localhost:5001"
    echo ""
    echo -e "${CLR_GOLD}[note] Port 5000 is currently occupied (typically macOS AirPlay Receiver).${CLR_RESET}"
    echo -e "${CLR_GOLD}       GrizzDog-AI will automatically start on port 5001 instead.${CLR_RESET}"
fi

echo ""
echo -e "${CLR_GREEN}==================================================================${CLR_RESET}"
echo -e "${CLR_PURPLE}🐾 GrizzDog-AI is installed and ready to run!${CLR_RESET}"
echo -e "${CLR_GREEN}==================================================================${CLR_RESET}"
echo ""
echo "To start the lab anytime:"
echo -e "  ${CLR_CYAN}cd ${TARGET_DIR}${CLR_RESET}"
echo -e "  ${CLR_CYAN}./start.sh${CLR_RESET}"
echo ""
echo -e "The Cyber Defense Gateway will be available at: ${CLR_GOLD}${PORT_INFO}${CLR_RESET}"
echo ""

# Interactive launch prompt if connected to terminal
LAUNCH_NOW=""
if [ -t 0 ] || [ -c /dev/tty ]; then
    read -r -p "Would you like to start GrizzDog-AI right now? [Y/n] " LAUNCH_NOW </dev/tty || true
    if [[ "$LAUNCH_NOW" =~ ^[Nn] ]]; then
        echo "Exiting setup. Run './start.sh' when you are ready!"
        exit 0
    else
        echo "Starting GrizzDog-AI gateway..."
        exec ./start.sh
    fi
fi

