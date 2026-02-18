#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  GuardClaw — One-command installer (macOS / Linux)
#  Usage: curl -sSL https://raw.githubusercontent.com/YOUR_REPO/main/install.sh | bash
#   or:   bash install.sh
# ══════════════════════════════════════════════════════════════════

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

say()  { echo -e "${GREEN}[GuardClaw]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
step() { echo -e "\n${CYAN}── $1${NC}"; }

echo ""
echo -e "${GREEN}"
echo "  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗  ██████╗██╗      █████╗ ██╗    ██╗"
echo "  ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██║     ██╔══██╗██║    ██║"
echo "  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║     ██║     ███████║██║ █╗ ██║"
echo "  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║     ██║     ██╔══██║██║███╗██║"
echo "  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝╚██████╗███████╗██║  ██║╚███╔███╔╝"
echo "   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝"
echo -e "${NC}"
echo "  Security Bouncer for Users & AI Agents — v4.3.0"
echo "  100% local. No data leaves your machine."
echo ""

# ── 1. Python check ───────────────────────────────────────────────
step "Checking Python"
if ! command -v python3 &>/dev/null; then
    err "Python 3.9+ is required. Install from https://python.org"
fi
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [[ "$PY_MAJOR" -lt 3 ]] || [[ "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 9 ]]; then
    err "Python 3.9+ required, found $PY_VER"
fi
say "Python $PY_VER ✓"

# ── 2. pip dependencies ───────────────────────────────────────────
step "Installing Python dependencies"
if python3 -m pip install -q customtkinter pyperclip requests; then
    say "Core dependencies installed ✓"
else
    err "pip install failed. Try: python3 -m pip install customtkinter pyperclip requests"
fi

# Optional: httpx for async support
if python3 -m pip install -q httpx 2>/dev/null; then
    say "httpx (async support) installed ✓"
else
    warn "httpx not installed — async mode unavailable (optional)"
fi

# ── 3. Ollama check / install ─────────────────────────────────────
step "Checking Ollama"
if command -v ollama &>/dev/null; then
    OLLAMA_VER=$(ollama --version 2>/dev/null || echo "installed")
    say "Ollama $OLLAMA_VER ✓"
else
    warn "Ollama not found. Installing..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &>/dev/null; then
            brew install ollama
        else
            warn "Homebrew not found. Download Ollama manually from https://ollama.ai"
            warn "Then run: ollama serve && ollama pull qwen2.5-coder:1.5b"
        fi
    else
        # Linux
        curl -fsSL https://ollama.ai/install.sh | sh || warn "Ollama auto-install failed. See https://ollama.ai"
    fi
fi

# ── 4. Pull a default model ───────────────────────────────────────
step "Pulling default AI model (qwen2.5-coder:1.5b — ~1 GB)"
echo "  This is the lightweight model. For better accuracy: ollama pull qwen2.5-coder:7b"
echo ""
if command -v ollama &>/dev/null; then
    # Start ollama serve in background if not running
    if ! curl -sf http://localhost:11434/api/tags &>/dev/null; then
        say "Starting Ollama server..."
        ollama serve &>/dev/null &
        sleep 3
    fi
    if ollama pull qwen2.5-coder:1.5b; then
        say "Model ready ✓"
    else
        warn "Model pull failed. Run manually: ollama pull qwen2.5-coder:1.5b"
    fi
else
    warn "Skipping model pull (Ollama not available)"
fi

# ── 5. Verify guardclaw.py is present ────────────────────────────
step "Verifying GuardClaw"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f "$SCRIPT_DIR/guardclaw.py" ]]; then
    err "guardclaw.py not found in $SCRIPT_DIR. Make sure you cloned the full repository."
fi
if python3 -c "import ast; ast.parse(open('$SCRIPT_DIR/guardclaw.py').read())" 2>/dev/null; then
    say "guardclaw.py syntax OK ✓"
else
    err "guardclaw.py has a syntax error. Try re-downloading the repository."
fi

# ── 6. Optional: OpenClaw skill install ──────────────────────────
step "OpenClaw integration (optional)"
OPENCLAW_SKILLS="${HOME}/.openclaw/workspace/skills"
if [[ -d "$OPENCLAW_SKILLS" ]]; then
    SKILL_DIR="$OPENCLAW_SKILLS/guardclaw"
    mkdir -p "$SKILL_DIR"
    cp "$SCRIPT_DIR/SKILL.md" "$SKILL_DIR/SKILL.md" 2>/dev/null || true
    if [[ -f "$SKILL_DIR/SKILL.md" ]]; then
        say "GuardClaw skill installed to OpenClaw ✓"
        say "  → Your agent will now use GuardClaw before executing tools."
    fi
else
    warn "OpenClaw not detected at ~/.openclaw/ — skipping skill install"
    warn "To integrate manually: copy SKILL.md to ~/.openclaw/workspace/skills/guardclaw/"
fi

# ── 7. Done ───────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  GuardClaw installed successfully!${NC}"
echo ""
echo "  Launch GUI:    python3 guardclaw.py"
echo "  CLI scan:      python3 guardclaw.py --scan <file>"
echo "  CI/CD:         python3 guardclaw.py --text 'code here' --mode bouncer"
echo ""
echo "  Library API:   from guardclaw import Protector"
echo ""
echo "  Docs:          https://github.com/YOUR_REPO/guardclaw"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""
