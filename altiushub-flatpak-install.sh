#!/usr/bin/env bash
###############################################################################
# AltiusHub — Unified App Deployment Script   (run BEFORE the MDM policy)
# -----------------------------------------------------------------------------
# Target:   Debian / Ubuntu (amd64)
# Run as:   root   ->   sudo bash altiushub-app-deploy.sh
# Push via: Scalefusion script job (fetch + run, one shot)
#
# ORDER: Run this FIRST. The MDM hardening policy later locks down apt/dpkg/
#        snap/flatpak, so every install has to happen here while the package
#        managers are still open.
#
# Installs (soft-fail: one bad app never stops the rest):
#   Flatpak (Flathub):  VS Code, Postman, pgAdmin4, DBeaver, draw.io, Zed,
#                       GitHub Desktop
#   Official .deb/repo: Google Chrome, Microsoft Edge
#                       -> official builds so they read
#                          /etc/opt/{chrome,edge}/policies/managed/ — the exact
#                          paths the extension-block policy writes to
#   Microsoft repo:     Azure VPN Client
#   Docker repo/.deb:   Docker Desktop
#   Direct binaries:    kubectl, Minikube
#   AppImage:           Dr. Sprinto
#   JetBrains:          PyCharm (direct to /opt) + Toolbox App (staged)
#
# Log:     /var/log/altiushub-app-deploy.log
# Summary: /tmp/altiushub-app-deploy-summary.txt
###############################################################################

set -uo pipefail

# ============================ CONFIG =========================================
LOG_FILE="/var/log/altiushub-app-deploy.log"
SUMMARY_FILE="/tmp/altiushub-app-deploy-summary.txt"

# Download URLs (override here if a vendor changes a path)
CHROME_DEB_URL="https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
MS_KEY_URL="https://packages.microsoft.com/keys/microsoft.asc"
DOCKER_DEB_URL="https://desktop.docker.com/linux/main/amd64/docker-desktop-amd64.deb"
MINIKUBE_URL="https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64"
DRSPRINTO_URL="https://github.com/LolzMartiz/Arc-Angel/raw/refs/heads/main/DrSprinto-4.0.7.AppImage"
PYCHARM_URL="https://data.services.jetbrains.com/products/download?code=PCP&platform=linux"
TOOLBOX_URL="https://data.services.jetbrains.com/products/download?code=TBA&platform=linux"

# Install targets
DRSPRINTO_PATH="/opt/altiushub/DrSprinto.AppImage"
PYCHARM_DIR="/opt/pycharm"
TOOLBOX_DIR="/opt/jetbrains-toolbox"

# Flathub app list  ("Friendly Name|flathub.app.id")
FLATPAK_APPS=(
  "VS Code|com.visualstudio.code"
  "Postman|com.getpostman.Postman"
  "pgAdmin4|org.pgadmin.pgadmin4"
  "DBeaver CE|io.dbeaver.DBeaverCommunity"
  "draw.io|com.jgraph.drawio.desktop"
  "Zed IDE|dev.zed.Zed"
  "GitHub Desktop|io.github.shiftey.Desktop"
)

declare -A RESULT
declare -A DETAIL

# ============================ HELPERS ========================================
log() { printf '[%(%F %T)T] %s\n' -1 "$*" | tee -a "$LOG_FILE"; }
section() { log ""; log "================================================================"; log "  $*"; log "================================================================"; }
mark() { RESULT["$1"]="$2"; DETAIL["$1"]="$3"; log "[$2] $1 — $3"; }
have() { command -v "$1" >/dev/null 2>&1; }
apt_get() { DEBIAN_FRONTEND=noninteractive apt-get "$@" >>"$LOG_FILE" 2>&1; }

# Install a list of packages, tolerating individual failures
apt_install_soft() {
  local p
  for p in "$@"; do
    apt_get install -y --no-install-recommends "$p" || log "  (package '$p' not installed — continuing)"
  done
}

# ============================ PREFLIGHT ======================================
[[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }
mkdir -p "$(dirname "$LOG_FILE")"; touch "$LOG_FILE"; chmod 600 "$LOG_FILE"

section "PREFLIGHT"
log "Host: $(hostname)"
log "OS:   $(. /etc/os-release && echo "$PRETTY_NAME")"

# OS facts (used for repos)
. /etc/os-release
DISTRO_ID="${ID:-ubuntu}"
CODENAME="${VERSION_CODENAME:-jammy}"
DOCKER_CODENAME="${UBUNTU_CODENAME:-$CODENAME}"
VERSION_ID_NUM="${VERSION_ID:-22.04}"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
log "Distro: $DISTRO_ID  Codename: $CODENAME  Version: $VERSION_ID_NUM  Arch: $ARCH"
if [[ "$ARCH" != "amd64" ]]; then
  log "WARNING: this script assumes amd64 download URLs. Arch is '$ARCH' — some apps may fail."
fi

# Internet check (ICMP first, HTTPS fallback for ping-blocked networks)
if ! ping -c1 -W3 8.8.8.8 >/dev/null 2>&1 && ! curl -fsS --max-time 6 -o /dev/null https://flathub.org >/dev/null 2>&1; then
  log "FATAL: no internet connectivity"; exit 2
fi

export DEBIAN_FRONTEND=noninteractive
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT

###############################################################################
# BASE DEPENDENCIES
###############################################################################
section "BASE DEPENDENCIES"
log "apt-get update..."
apt_get update || log "apt update reported errors (continuing)"

log "Installing common tooling + GUI/runtime prerequisites..."
apt_install_soft \
  ca-certificates curl wget gnupg lsb-release apt-transport-https tar \
  libxi6 libxrender1 libxtst6 mesa-utils libfontconfig1 libgtk-3-bin \
  dbus-user-session
# AppImage runtime (package name differs on 24.04+)
apt_get install -y libfuse2 || apt_get install -y libfuse2t64 || log "  (libfuse2 not installed — AppImages may need it)"

###############################################################################
# THIRD-PARTY APT REPOS  (added up front, single update afterwards)
###############################################################################
section "CONFIGURE THIRD-PARTY APT REPOS"
install -d -m 0755 /usr/share/keyrings /etc/apt/keyrings

# --- Microsoft signing key (shared by Edge repo + Azure VPN prod repo) ---
if curl -fsSL "$MS_KEY_URL" | gpg --dearmor --yes -o /usr/share/keyrings/microsoft-prod.gpg 2>>"$LOG_FILE"; then
  log "Microsoft signing key installed."
else
  log "WARNING: failed to fetch Microsoft signing key — Edge / Azure VPN may fail."
fi

# --- Microsoft Edge repo ---
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/repos/edge stable main" \
  > /etc/apt/sources.list.d/microsoft-edge.list
log "Edge repo configured."

# --- Azure VPN (Microsoft Ubuntu prod) repo ---
if curl -fsSL "https://packages.microsoft.com/config/ubuntu/${VERSION_ID_NUM}/prod.list" \
     -o /etc/apt/sources.list.d/microsoft-prod.list 2>>"$LOG_FILE"; then
  log "Microsoft prod repo configured (Ubuntu ${VERSION_ID_NUM})."
else
  log "WARNING: Microsoft prod repo not available for '${VERSION_ID_NUM}' — Azure VPN may fail (Ubuntu-only)."
fi

# --- Docker CE repo (satisfies docker-desktop dependencies) ---
if curl -fsSL "https://download.docker.com/linux/${DISTRO_ID}/gpg" -o /etc/apt/keyrings/docker.asc 2>>"$LOG_FILE"; then
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${DISTRO_ID} ${DOCKER_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  log "Docker repo configured (${DISTRO_ID} ${DOCKER_CODENAME})."
else
  log "WARNING: failed to fetch Docker key — Docker Desktop deps may not resolve."
fi

log "Refreshing package lists with new repos..."
apt_get update || log "apt update reported errors after adding repos (continuing)"

###############################################################################
# MODULE 1 — FLATPAK APPS
###############################################################################
section "FLATPAK RUNTIME + FLATHUB"
if have flatpak; then
  log "flatpak present: $(flatpak --version)"
else
  log "Installing flatpak..."
  if apt_get install -y flatpak; then
    log "flatpak installed: $(flatpak --version)"
  else
    log "flatpak install failed — all Flatpak apps will be skipped."
  fi
fi

if have flatpak; then
  if flatpak remote-list --system 2>/dev/null | grep -q '^flathub'; then
    log "Flathub remote already configured."
  else
    log "Adding Flathub remote (system-wide)..."
    flatpak remote-add --system --if-not-exists flathub \
      https://flathub.org/repo/flathub.flatpakrepo >>"$LOG_FILE" 2>&1 \
      && log "Flathub remote added." || log "Failed to add Flathub remote."
  fi

  section "INSTALL FLATPAK APPS"
  for entry in "${FLATPAK_APPS[@]}"; do
    name="${entry%%|*}"; appid="${entry##*|}"
    if flatpak list --system --app --columns=application 2>/dev/null | grep -qx "$appid"; then
      mark "$name" SKIP "already installed ($appid)"; continue
    fi
    log "Installing $name ($appid)..."
    if flatpak install -y --system --noninteractive flathub "$appid" >>"$LOG_FILE" 2>&1; then
      mark "$name" OK "installed (flatpak)"
    else
      mark "$name" FAIL "flatpak install failed — check log"
    fi
  done
else
  for entry in "${FLATPAK_APPS[@]}"; do
    mark "${entry%%|*}" FAIL "flatpak runtime unavailable"
  done
fi

###############################################################################
# MODULE 2 — GOOGLE CHROME (official .deb)
###############################################################################
section "GOOGLE CHROME"
if have google-chrome || have google-chrome-stable; then
  mark "Google Chrome" SKIP "already installed"
else
  if curl -fsSL "$CHROME_DEB_URL" -o "$TMP_ROOT/chrome.deb" \
     && apt_get install -y "$TMP_ROOT/chrome.deb"; then
    mark "Google Chrome" OK "installed (reads /etc/opt/chrome/policies/managed/)"
  else
    mark "Google Chrome" FAIL "download or install failed — check log"
  fi
fi

###############################################################################
# MODULE 3 — MICROSOFT EDGE (official repo)
###############################################################################
section "MICROSOFT EDGE"
if have microsoft-edge || have microsoft-edge-stable; then
  mark "Microsoft Edge" SKIP "already installed"
else
  if apt_get install -y microsoft-edge-stable; then
    mark "Microsoft Edge" OK "installed (reads /etc/opt/edge/policies/managed/)"
  else
    mark "Microsoft Edge" FAIL "install failed — check repo/key in log"
  fi
fi

###############################################################################
# MODULE 4 — AZURE VPN CLIENT (Microsoft repo)
###############################################################################
section "AZURE VPN CLIENT"
if dpkg -s microsoft-azurevpnclient >/dev/null 2>&1; then
  mark "Azure VPN Client" SKIP "already installed"
else
  if apt_get install -y microsoft-azurevpnclient; then
    mark "Azure VPN Client" OK "installed"
  else
    mark "Azure VPN Client" FAIL "install failed (Ubuntu-only package) — check log"
  fi
fi

###############################################################################
# MODULE 5 — DOCKER DESKTOP (.deb + repo deps)
###############################################################################
section "DOCKER DESKTOP"
if dpkg -s docker-desktop >/dev/null 2>&1; then
  mark "Docker Desktop" SKIP "already installed"
else
  log "Installing virtualization dependencies..."
  apt_install_soft qemu-system-x86 qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils
  if curl -fsSL "$DOCKER_DEB_URL" -o "$TMP_ROOT/docker-desktop.deb" \
     && apt_get install -y "$TMP_ROOT/docker-desktop.deb"; then
    # NOTE: Docker Desktop runs as a per-user service and starts on user login.
    # 'systemctl --user' can't be driven from root, so we don't start it here.
    mark "Docker Desktop" OK "installed (starts per-user on login)"
  else
    mark "Docker Desktop" FAIL "download or install failed — check log"
  fi
fi

###############################################################################
# MODULE 6 — kubectl + Minikube (direct binaries)
###############################################################################
section "kubectl + MINIKUBE"

# kubectl
if have kubectl; then
  mark "kubectl" SKIP "already installed"
else
  KVER="$(curl -L -s https://dl.k8s.io/release/stable.txt 2>/dev/null)"
  if [[ -n "$KVER" ]] \
     && curl -fsSLo "$TMP_ROOT/kubectl" "https://dl.k8s.io/release/${KVER}/bin/linux/${ARCH}/kubectl" \
     && install -m 0755 "$TMP_ROOT/kubectl" /usr/local/bin/kubectl; then
    mark "kubectl" OK "installed ${KVER} (/usr/local/bin/kubectl)"
  else
    mark "kubectl" FAIL "download or install failed — check log"
  fi
fi

# Minikube  (binary only — 'minikube start' is a runtime action, not provisioning)
if have minikube; then
  mark "Minikube" SKIP "already installed"
else
  if curl -fsSLo "$TMP_ROOT/minikube" "${MINIKUBE_URL%amd64}${ARCH}" \
     && install -m 0755 "$TMP_ROOT/minikube" /usr/local/bin/minikube; then
    mark "Minikube" OK "installed (/usr/local/bin/minikube)"
  else
    mark "Minikube" FAIL "download or install failed — check log"
  fi
fi

###############################################################################
# MODULE 7 — DR. SPRINTO (AppImage)
###############################################################################
section "DR. SPRINTO"
if [[ -x "$DRSPRINTO_PATH" ]]; then
  mark "Dr. Sprinto" SKIP "already present ($DRSPRINTO_PATH)"
else
  install -d -m 0755 "$(dirname "$DRSPRINTO_PATH")"
  if curl -fsSL "$DRSPRINTO_URL" -o "$DRSPRINTO_PATH"; then
    chmod 0755 "$DRSPRINTO_PATH"
    ln -sf "$DRSPRINTO_PATH" /usr/local/bin/drsprinto
    cat > /usr/share/applications/drsprinto.desktop <<EOF
[Desktop Entry]
Name=Dr. Sprinto
Exec=$DRSPRINTO_PATH
Type=Application
Categories=Utility;Security;
Terminal=false
EOF
    mark "Dr. Sprinto" OK "installed ($DRSPRINTO_PATH)"
  else
    mark "Dr. Sprinto" FAIL "download failed — check URL/log"
  fi
fi

###############################################################################
# MODULE 8 — JETBRAINS: PyCharm (direct) + Toolbox (staged)
###############################################################################
section "JETBRAINS PYCHARM + TOOLBOX"

# --- PyCharm direct to /opt (reliable, headless, fleet-wide) ---
if [[ -d "$PYCHARM_DIR" ]]; then
  mark "PyCharm" SKIP "already present ($PYCHARM_DIR)"
else
  pyc_tmp="$TMP_ROOT/pycharm"; mkdir -p "$pyc_tmp"
  if curl -fSL "$PYCHARM_URL" -o "$pyc_tmp/pycharm.tar.gz" 2>>"$LOG_FILE" \
     && tar -xzf "$pyc_tmp/pycharm.tar.gz" -C "$pyc_tmp" 2>>"$LOG_FILE"; then
    src="$(find "$pyc_tmp" -maxdepth 1 -type d -name 'pycharm*' | head -n1)"
    if [[ -n "$src" ]]; then
      rm -rf "$PYCHARM_DIR"; mv "$src" "$PYCHARM_DIR"
      # Launcher name varies by version
      if   [[ -f "$PYCHARM_DIR/bin/pycharm.sh" ]]; then pyc_bin="$PYCHARM_DIR/bin/pycharm.sh"
      elif [[ -f "$PYCHARM_DIR/bin/pycharm"    ]]; then pyc_bin="$PYCHARM_DIR/bin/pycharm"
      else pyc_bin=""; fi
      if [[ -n "$pyc_bin" ]]; then
        ln -sf "$pyc_bin" /usr/local/bin/pycharm
        cat > /usr/share/applications/pycharm.desktop <<EOF
[Desktop Entry]
Name=PyCharm
Exec=$pyc_bin %f
Icon=$PYCHARM_DIR/bin/pycharm.svg
Type=Application
Categories=Development;IDE;
Terminal=false
StartupWMClass=jetbrains-pycharm
EOF
        mark "PyCharm" OK "installed ($PYCHARM_DIR)"
      else
        mark "PyCharm" FAIL "extracted but launcher not found"
      fi
    else
      mark "PyCharm" FAIL "archive extracted but no pycharm* dir"
    fi
  else
    mark "PyCharm" FAIL "download or extract failed — check log"
  fi
fi

# --- JetBrains Toolbox (staged binary; per-user GUI, manages IDE versions) ---
if [[ -d "$TOOLBOX_DIR" ]]; then
  mark "JetBrains Toolbox" SKIP "already present ($TOOLBOX_DIR)"
else
  tb_tmp="$TMP_ROOT/toolbox"; mkdir -p "$tb_tmp"
  if curl -fSL "$TOOLBOX_URL" -o "$tb_tmp/toolbox.tar.gz" 2>>"$LOG_FILE" \
     && tar -xzf "$tb_tmp/toolbox.tar.gz" -C "$tb_tmp" 2>>"$LOG_FILE"; then
    src="$(find "$tb_tmp" -maxdepth 1 -type d -name 'jetbrains-toolbox*' | head -n1)"
    if [[ -n "$src" ]]; then
      rm -rf "$TOOLBOX_DIR"; mv "$src" "$TOOLBOX_DIR"
      tb_bin="$(find "$TOOLBOX_DIR" -type f -name 'jetbrains-toolbox' | head -n1)"
      if [[ -n "$tb_bin" ]]; then
        chmod 0755 "$tb_bin"; ln -sf "$tb_bin" /usr/local/bin/jetbrains-toolbox
        mark "JetBrains Toolbox" OK "staged ($TOOLBOX_DIR) — launch per-user to manage IDEs"
      else
        mark "JetBrains Toolbox" FAIL "binary not found after extract"
      fi
    else
      mark "JetBrains Toolbox" FAIL "no jetbrains-toolbox* dir after extract"
    fi
  else
    mark "JetBrains Toolbox" FAIL "download or extract failed — check log"
  fi
fi

###############################################################################
# SUMMARY
###############################################################################
section "SUMMARY"
{
  printf '\n%-22s %-7s %s\n' "APPLICATION" "STATUS" "DETAIL"
  printf '%-22s %-7s %s\n'   "-----------" "------" "------"
  for app in "${!RESULT[@]}"; do
    printf '%-22s %-7s %s\n' "$app" "${RESULT[$app]}" "${DETAIL[$app]}"
  done | sort
} | tee "$SUMMARY_FILE" | tee -a "$LOG_FILE"

ok=0; fail=0; skip=0
for s in "${RESULT[@]}"; do
  case "$s" in OK) ok=$((ok+1));; FAIL) fail=$((fail+1));; SKIP) skip=$((skip+1));; esac
done

log ""
log "RESULTS — OK:$ok  SKIP:$skip  FAIL:$fail"
log "Log:     $LOG_FILE"
log "Summary: $SUMMARY_FILE"
log ""
log "Chrome + Edge are official builds — they read policy from"
log "  /etc/opt/chrome/policies/managed/  and  /etc/opt/edge/policies/managed/"
log "so the extension block/allowlist policy will apply once that script runs."
log ""
log "Run the MDM hardening policy AFTER this script (it locks down installs)."

# Exit 0 so a single optional-app failure doesn't fail the whole MDM job.
# Read the summary table / FAIL count above for per-app status.
exit 0
