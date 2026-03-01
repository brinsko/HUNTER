#!/usr/bin/env bash
# Open Redirect Hunter — Bootstrap Installer (Silent by Default)

set -euo pipefail

REPO_BASE="https://raw.githubusercontent.com/YOUR_USERNAME/open-redirect-hunter/main"

VERBOSE=0
[[ "${1:-}" == "--verbose" ]] && VERBOSE=1

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log() { [[ $VERBOSE -eq 1 ]] && echo -e "$1"; }
ok()  { [[ $VERBOSE -eq 1 ]] && echo -e "${GREEN}[OK]${NC} $1"; }
fail() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

run_cmd() {
  if [[ $VERBOSE -eq 1 ]]; then
    "$@"
  else
    "$@" >/dev/null 2>&1
  fi
}

require_bin() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 not installed"
  ok "$1 detected"
}

############################################
# 1️⃣ System Requirements
############################################

log "Checking system..."

for bin in python3 go curl; do
  require_bin "$bin"
done

############################################
# 2️⃣ Download Core Files
############################################

FILES=("or_hunter.sh" "finder.py" "dashboard.py")

for file in "${FILES[@]}"; do
  if [[ ! -f "$file" ]]; then
    log "Downloading $file"
    run_cmd curl -sSfL "$REPO_BASE/$file" -o "$file" || fail "Download failed: $file"
  fi
done

chmod +x or_hunter.sh || fail "Failed to set executable permission"

############################################
# 3️⃣ Required Text Files
############################################

[[ -f domains.txt ]] || touch domains.txt

if [[ ! -f redirect_params.txt ]]; then
  run_cmd curl -sSfL "$REPO_BASE/redirect_params.txt" -o redirect_params.txt \
    || echo "redirect" > redirect_params.txt
fi

############################################
# 4️⃣ Python Environment
############################################

if [[ ! -d venv ]]; then
  run_cmd python3 -m venv venv || fail "Failed to create virtual environment"
fi

source venv/bin/activate || fail "Failed to activate virtual environment"

run_cmd python -m pip install --upgrade pip setuptools wheel

PY_PACKAGES=(flask flask_socketio requests reportlab)

for pkg in "${PY_PACKAGES[@]}"; do
  python -c "import $pkg" 2>/dev/null || run_cmd pip install "$pkg"
done

############################################
# 5️⃣ Go Tools
############################################

export PATH="$HOME/go/bin:$PATH"

declare -A GO_TOOLS=(
  [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
  [nuclei]="github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
  [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
  [gau]="github.com/lc/gau/v2/cmd/gau@latest"
  [waybackurls]="github.com/tomnomnom/waybackurls@latest"
  [gf]="github.com/tomnomnom/gf@latest"
  [qsreplace]="github.com/tomnomnom/qsreplace@latest"
  [ffuf]="github.com/ffuf/ffuf@latest"
  [unfurl]="github.com/tomnomnom/unfurl@latest"
)

for tool in "${!GO_TOOLS[@]}"; do
  command -v "$tool" >/dev/null 2>&1 || run_cmd go install "${GO_TOOLS[$tool]}"
done

############################################
# 6️⃣ Nuclei Templates
############################################

run_cmd nuclei -update-templates || true

############################################
# DONE
############################################

echo
echo -e "${GREEN}Installation Complete.${NC}"
echo
echo "Run:"
echo "  source venv/bin/activate"
echo "  ./or_hunter.sh" also tell them to add domain/subdomain in domains.txtecho
echo -e "${GREEN}Installation Complete.${NC}"
echo
echo "Next Steps:"
echo
echo "1. Add target domain(s) or subdomain(s) to:"
echo "      domains.txt"
echo
echo "   Example:"
echo "      example.com"
echo "      api.example.com"
echo
echo "2. Activate the environment:"
echo "      source venv/bin/activate"
echo
echo "3. Run the scanner:"
echo "      ./or_hunter.sh"
echo
