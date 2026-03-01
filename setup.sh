#!/usr/bin/env bash
set -u

# ─────────────────────────────
# Color Definitions
# ─────────────────────────────
RED='\033[0;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# ─────────────────────────────
# Banner
# ─────────────────────────────
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo -e "   ${GREEN}⚔  Open Redirect Hunter${NC}"
echo -e "   ${WHITE}Security Automation Framework${NC}"
echo
echo -e "   ${YELLOW}Author  : Brinsko${NC}"
echo -e "   ${MAGENTA}Version : 1.0${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo

fail() { echo -e "${RED}[FAIL]${NC} $1"; }
pass() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

cmd_exists() {
  command -v "$1" >/dev/null 2>&1
}

# ─────────────────────────────
# 1. System basics
# ─────────────────────────────
echo "[1] System basics"

if cmd_exists go; then
  pass "Go installed ($(go version | awk '{print $3}'))"
else
  fail "Go not installed"
  exit 1
fi

if cmd_exists python3; then
  pass "Python3 installed"
else
  fail "Python3 not installed"
  exit 1
fi

if cmd_exists git; then
  pass "Git installed"
else
  fail "Git not installed"
  exit 1
fi

# ─────────────────────────────
# 2. Go tools
# ─────────────────────────────
echo
echo "[2] Go-based tools"

tools=(
  subfinder
  amass
  dnsx
  httpx
  nuclei
  gau
  gf
  qsreplace
  ffuf
  waybackurls
)

for t in "${tools[@]}"; do
  if cmd_exists "$t"; then
    pass "$t installed"
  else
    warn "$t missing (install manually if needed)"
  fi
done

# ─────────────────────────────
# 3. Python packages (Dashboard + Core)
# ─────────────────────────────
echo
echo "[3] Python packages"

declare -A packages=(
  [flask]="flask"
  [flask_socketio]="flask_socketio"
  [eventlet]="eventlet"
  [uro]="uro"
  [requests]="requests"
  [reportlab]="reportlab"
)

for pkg in "${!packages[@]}"; do
  module="${packages[$pkg]}"

  if python3 -c "import $module" 2>/dev/null; then
    pass "$pkg installed"
  else
    info "Installing $pkg..."

    if [[ -n "${VIRTUAL_ENV:-}" ]]; then
      pip install "$pkg" >/dev/null 2>&1
    else
      python3 -m pip install --user "$pkg" >/dev/null 2>&1
    fi

    if python3 -c "import $module" 2>/dev/null; then
      pass "$pkg installed successfully"
    else
      fail "$pkg installation failed"
      exit 1
    fi
  fi
done

# ─────────────────────────────
# 4. ParamSpider
# ─────────────────────────────
echo
echo "[4] ParamSpider"

if cmd_exists paramspider; then
  pass "ParamSpider installed"
else
  info "Installing ParamSpider from GitHub..."

  if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    pip install git+https://github.com/devanshbatham/ParamSpider.git >/dev/null 2>&1
  else
    python3 -m pip install --user git+https://github.com/devanshbatham/ParamSpider.git >/dev/null 2>&1
  fi

  if cmd_exists paramspider; then
    pass "ParamSpider installed successfully"
  else
    fail "ParamSpider installation failed"
    exit 1
  fi
fi

# ─────────────────────────────
# 5. LOXS auto-download & move
# ─────────────────────────────
echo
echo "[5] LOXS scanner"

if [[ -f loxs.py ]]; then
  pass "LOXS already present"
else
  info "Downloading LOXS..."

  [[ -d loxs ]] && rm -rf loxs
  git clone https://github.com/coffinxp/loxs.git >/dev/null 2>&1

  if [[ -d loxs ]]; then
    shopt -s dotglob
    mv loxs/* .
    shopt -u dotglob
    rm -rf loxs
    pass "LOXS downloaded and ready"
  else
    fail "Failed to clone LOXS repository"
    exit 1
  fi
fi

# ─────────────────────────────
# 6. Nuclei templates
# ─────────────────────────────
echo
echo "[6] Nuclei templates"

if ls ~/nuclei-templates/http/vulnerabilities/generic/open-redirect*.yaml >/dev/null 2>&1; then
  pass "Open-redirect templates found"
else
  warn "Open-redirect templates not found (run: nuclei -update-templates)"
fi

# ─────────────────────────────
# 7. Input files
# ─────────────────────────────
echo
echo "[7] Input files"

if [[ -f domains.txt && -s domains.txt ]]; then
  pass "domains.txt exists"
else
  fail "domains.txt missing or empty"
  exit 1
fi

if [[ -f redirect_params.txt && -s redirect_params.txt ]]; then
  pass "redirect_params.txt exists"
else
  fail "redirect_params.txt missing or empty"
  exit 1
fi

# ─────────────────────────────
# Done
# ─────────────────────────────
echo
echo "═══════════════════════════════════════════════"
echo -e "${GREEN}[✓] Environment Ready.${NC}"
echo
echo -e "Next Step:"
echo -e "  ➜ Add your target domain or subdomain inside ${YELLOW}domains.txt${NC}"
echo
echo -e "  Example format inside ${YELLOW}domains.txt${NC}:"
echo -e "      ${GREEN}example.com${NC}"
echo -e "      ${GREEN}sub.example.com${NC}"
echo
echo -e "Then run:"
echo -e "  ➜ ${GREEN}./or_hunter.sh${NC}"
echo "═══════════════════════════════════════════════"
