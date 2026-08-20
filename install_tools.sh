#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# W!ldC4rd – Dependency Installer
# Installs all required external tools for authorized security reconnaissance.
#
# Tools installed:
#   System   : whois, git, python3
#   Go       : subfinder, amass, assetfinder, httpx, waybackurls, gau,
#              uro, gf, katana
#   Python   : xnLinkFinder
#   Other    : EyeWitness (screenshots + HTML report)
#   Patterns : GF patterns (1ndianl33t collection)
#
# Run with: bash install_tools.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'; CYAN='\033[96m'; RESET='\033[0m'
info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
err()   { echo -e "${RED}[ERROR]${RESET} $*"; }

# ── Detect Go installation ────────────────────────────────────────────────────
require_go() {
    if ! command -v go &>/dev/null; then
        err "Go is not installed. Install it from https://go.dev/dl and re-run this script."
        exit 1
    fi
    info "Go found: $(go version)"
}

# ── Install Go-based tools ────────────────────────────────────────────────────
install_go_tool() {
    local name="$1" pkg="$2"
    if command -v "$name" &>/dev/null; then
        ok "$name already installed ($(command -v "$name"))"
        return
    fi
    info "Installing $name …"
    if go install "$pkg" 2>&1; then
        ok "$name installed"
    else
        warn "$name installation failed — you may need to install it manually"
    fi
}

# ── Install Python tools ──────────────────────────────────────────────────────
install_python_tool() {
    local name="$1" repo="$2" script="$3"
    local target_dir="$HOME/tools/$name"

    if [[ -f "$target_dir/$script" ]]; then
        ok "$name already present at $target_dir/$script"
        return
    fi
    info "Cloning $name from $repo …"
    mkdir -p "$HOME/tools"
    if git clone --depth 1 "$repo" "$target_dir" 2>&1; then
        if [[ -f "$target_dir/requirements.txt" ]]; then
            pip3 install -r "$target_dir/requirements.txt" --break-system-packages --quiet 2>&1 || true
        fi
        ok "$name cloned → $target_dir/$script"
    else
        warn "$name clone failed — install manually from $repo"
    fi
}

# ── apt packages ──────────────────────────────────────────────────────────────
info "Updating apt and installing system packages …"
sudo apt-get update -qq
sudo apt-get install -y -qq whois git python3 python3-pip 2>&1

# ── Python dependencies ───────────────────────────────────────────────────────
info "Installing Python dependencies …"
pip3 install requests urllib3 --break-system-packages --quiet 2>&1 || \
    sudo apt-get install -y -qq python3-requests python3-urllib3

# ── Go tools ──────────────────────────────────────────────────────────────────
require_go
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin"

# Core enumeration
install_go_tool "subfinder"    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "amass"        "github.com/owasp-amass/amass/v4/...@master"
install_go_tool "assetfinder"  "github.com/tomnomnom/assetfinder@latest"

# Probing
install_go_tool "httpx"        "github.com/projectdiscovery/httpx/cmd/httpx@latest"

# Historical URLs — waybackurls is primary, gau is fallback
install_go_tool "waybackurls"  "github.com/tomnomnom/waybackurls@latest"
install_go_tool "gau"          "github.com/lc/gau/v2/cmd/gau@latest"

# Deduplication & filtering
install_go_tool "uro"          "github.com/s0md3v/uro@latest"

# Pattern matching
install_go_tool "gf"           "github.com/tomnomnom/gf@latest"

# Crawling
install_go_tool "katana"       "github.com/projectdiscovery/katana/cmd/katana@latest"

# ── GF patterns ───────────────────────────────────────────────────────────────
GF_PATTERNS_DIR="$HOME/.gf"
if [[ ! -d "$GF_PATTERNS_DIR" ]]; then
    info "Installing GF patterns …"
    mkdir -p "$GF_PATTERNS_DIR"
    git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-patterns 2>&1
    cp /tmp/gf-patterns/*.json "$GF_PATTERNS_DIR/" 2>/dev/null || true
    ok "GF patterns installed to $GF_PATTERNS_DIR"
else
    ok "GF patterns already present at $GF_PATTERNS_DIR"
fi

# ── Python security tools ─────────────────────────────────────────────────────
# xnLinkFinder only — replaces LinkFinder (better) + SecretFinder (replaced by inline regex)
install_python_tool "xnLinkFinder" "https://github.com/xnl-h4ck3r/xnLinkFinder.git" "xnLinkFinder.py"

# Create symlink so it's accessible from PATH
if [[ -f "$HOME/tools/xnLinkFinder/xnLinkFinder.py" ]] && [[ ! -f "/usr/local/bin/xnLinkFinder" ]]; then
    sudo ln -sf "$HOME/tools/xnLinkFinder/xnLinkFinder.py" /usr/local/bin/xnLinkFinder
    sudo chmod +x "$HOME/tools/xnLinkFinder/xnLinkFinder.py"
    ok "xnLinkFinder symlinked to /usr/local/bin/xnLinkFinder"
fi

# Install xnLinkFinder deps
req="$HOME/tools/xnLinkFinder/requirements.txt"
[[ -f "$req" ]] && pip3 install -r "$req" --break-system-packages --quiet 2>&1 || true

# ── EyeWitness — screenshots & HTML reports ───────────────────────────────────
info "Installing EyeWitness …"
if command -v eyewitness &>/dev/null || command -v EyeWitness &>/dev/null; then
    ok "EyeWitness already installed ($(command -v eyewitness || command -v EyeWitness))"
else
    # Prefer apt on Kali/Debian — much simpler and includes all dependencies
    if apt-cache show eyewitness &>/dev/null 2>&1; then
        info "Installing EyeWitness via apt …"
        if sudo apt-get install -y -qq eyewitness 2>&1; then
            ok "EyeWitness installed via apt"
        else
            warn "apt install failed — falling back to source install"
            _ew_from_source=true
        fi
    else
        _ew_from_source=true
    fi

    if [[ "${_ew_from_source:-false}" == "true" ]]; then
        EW_DIR="$HOME/tools/EyeWitness"
        if git clone --depth 1 https://github.com/RedSiege/EyeWitness.git "$EW_DIR" 2>&1; then
            pip3 install -r "$EW_DIR/Python3/requirements.txt" \
                --break-system-packages --quiet 2>&1 || true
            sudo ln -sf "$EW_DIR/Python3/EyeWitness.py" /usr/local/bin/eyewitness
            sudo chmod +x "$EW_DIR/Python3/EyeWitness.py"
            ok "EyeWitness installed from source → /usr/local/bin/eyewitness"
        else
            warn "EyeWitness clone failed — install manually:"
            warn "  sudo apt install eyewitness"
            warn "  OR: https://github.com/RedSiege/EyeWitness"
        fi
    fi
fi

# ── PATH reminder ─────────────────────────────────────────────────────────────
echo ""
ok "All tools installed."
echo ""
echo -e "${CYAN}Add the following to your shell profile (~/.bashrc or ~/.zshrc):${RESET}"
echo -e "  export PATH=\"\$PATH:\$HOME/go/bin\""
echo -e "  export PATH=\"\$PATH:\$HOME/tools/xnLinkFinder\""
echo ""
echo -e "${GREEN}Then reload with:${RESET}  source ~/.bashrc"
echo ""
