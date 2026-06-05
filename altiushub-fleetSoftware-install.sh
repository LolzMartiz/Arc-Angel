#!/usr/bin/env bash
###############################################################################
# AltiusHub — Unified App Deployment Script   (run BEFORE the MDM policy)
# -----------------------------------------------------------------------------
# Target:   Debian / Ubuntu  (amd64 primary; arm64 supported for arch-portable
#           apps — vendor amd64-only apps will SKIP cleanly on arm64)
# Run as:   root   ->   sudo bash altiushub-app-deploy.sh
# Push via: Scalefusion script job (fetch + run, one shot)
#
# ORDER: Run this FIRST. The MDM hardening policy later locks down apt/dpkg/
#        snap/flatpak, so every install has to happen here while the package
#        managers are still open.
#
# Installs (soft-fail: one bad app never stops the rest):
#   Flatpak (Flathub):  VS Code, Postman, DBeaver, draw.io, Zed, GitHub Desktop
#   pgAdmin apt repo:   pgAdmin4                          (amd64 only)
#   Official .deb/repo: Google Chrome, Microsoft Edge     (amd64 only)
#                       -> read /etc/opt/{chrome,edge}/policies/managed/ which
#                          is exactly where the extension-block policy writes
#   Microsoft repo:     Azure VPN Client                  (amd64 only)
#   Docker repo/.deb:   Docker Desktop                    (amd64 only)
#   Direct binaries:    kubectl, Minikube                 (arch-portable)
#   AppImage:           Dr. Sprinto
#   JetBrains:          PyCharm (direct to /opt) + Toolbox App  (arch-aware URL)
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
PGADMIN_KEY_URL="https://www.pgadmin.org/static/packages_pgadmin_org.pub"
DOCKER_DEB_URL="https://desktop.docker.com/linux/main/amd64/docker-desktop-amd64.deb"
MINIKUBE_URL_BASE="https://storage.googleapis.com/minikube/releases/latest/minikube-linux"
DRSPRINTO_URL="https://github.com/LolzMartiz/Arc-Angel/raw/refs/heads/main/DrSprinto-4.0.7.AppImage"
JB_DOWNLOAD_BASE="https://data.services.jetbrains.com/products/download"

# Install targets
DRSPRINTO_PATH="/opt/altiushub/DrSprinto.AppImage"
PYCHARM_DIR="/opt/pycharm"
TOOLBOX_DIR="/opt/jetbrains-toolbox"

# Flathub app list  ("Friendly Name|flathub.app.id")
# pgAdmin4 is NOT on Flathub — handled via the pgAdmin apt repo below.
FLATPAK_APPS=(
  "VS Code|com.visualstudio.code"
  "Postman|com.getpostman.Postman"
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

. /etc/os-release
DISTRO_ID="${ID:-ubuntu}"
CODENAME="${VERSION_CODENAME:-jammy}"
DOCKER_CODENAME="${UBUNTU_CODENAME:-$CODENAME}"
VERSION_ID_NUM="${VERSION_ID:-22.04}"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo unknown)"
log "Distro: $DISTRO_ID  Codename: $CODENAME  Version: $VERSION_ID_NUM  Arch: $ARCH"

# Arch dispatch
IS_AMD64=0
case "$ARCH" in
  amd64)
    IS_AMD64=1
    JB_PLATFORM="linux"          # JetBrains x86_64 build
    MINIKUBE_ARCH="amd64"
    ;;
  arm64)
    JB_PLATFORM="linuxARM64"     # JetBrains aarch64 build
    MINIKUBE_ARCH="arm64"
    log "Note: vendor amd64-only apps (Chrome, Edge, Docker Desktop, Azure VPN, pgAdmin) will SKIP on arm64."
    ;;
  *)
    JB_PLATFORM="linux"
    MINIKUBE_ARCH="$ARCH"
    log "Note: arch '$ARCH' is unusual — most vendor apps will SKIP."
    ;;
esac

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
# THIRD-PARTY APT REPOS  (added up front, one update afterwards)
###############################################################################
section "CONFIGURE THIRD-PARTY APT REPOS"
install -d -m 0755 /usr/share/keyrings /etc/apt/keyrings

# --- Microsoft signing key (shared by Edge repo + Azure VPN prod repo) ---
if curl -fsSL "$MS_KEY_URL" | gpg --dearmor --yes -o /usr/share/keyrings/microsoft-prod.gpg 2>>"$LOG_FILE"; then
  log "Microsoft signing key installed."
else
  log "WARNING: failed to fetch Microsoft signing key — Edge / Azure VPN may fail."
fi

# --- Microsoft Edge repo (amd64 build only; harmless to add on arm64) ---
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/repos/edge stable main" \
  > /etc/apt/sources.list.d/microsoft-edge.list
log "Edge repo configured."

# --- Microsoft Ubuntu prod repo (Azure VPN client) ---
# Microsoft only ships microsoft-azurevpnclient for focal (20.04) and jammy
# (22.04). On any newer Ubuntu (noble 24.04 etc.) the host's own prod.list
# resolves to a repo that doesn't contain the package, which is why the
# previous behaviour failed with "Unable to locate package". Pinning to the
# jammy pool — tested working on noble where the jammy .deb (v3.0.0) installs
# cleanly against noble's libraries.
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/ubuntu/22.04/prod jammy main" \
  > /etc/apt/sources.list.d/microsoft-prod.list
log "Microsoft prod repo configured (jammy pool — Azure VPN compatibility)."

# --- Docker CE repo (satisfies docker-desktop dependencies) ---
if curl -fsSL "https://download.docker.com/linux/${DISTRO_ID}/gpg" -o /etc/apt/keyrings/docker.asc 2>>"$LOG_FILE"; then
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${DISTRO_ID} ${DOCKER_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  log "Docker repo configured (${DISTRO_ID} ${DOCKER_CODENAME})."
else
  log "WARNING: failed to fetch Docker key — Docker Desktop deps may not resolve."
fi

# --- pgAdmin repo ---
if curl -fsSL "$PGADMIN_KEY_URL" | gpg --dearmor --yes -o /usr/share/keyrings/packages-pgadmin-org.gpg 2>>"$LOG_FILE"; then
  echo "deb [signed-by=/usr/share/keyrings/packages-pgadmin-org.gpg] https://ftp.postgresql.org/pub/pgadmin/pgadmin4/apt/${CODENAME} pgadmin4 main" \
    > /etc/apt/sources.list.d/pgadmin4.list
  log "pgAdmin repo configured (${CODENAME})."
else
  log "WARNING: failed to fetch pgAdmin key — pgAdmin4 may fail."
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
# MODULE 2 — pgAdmin4  (official apt repo, amd64-only)
###############################################################################
section "pgAdmin4"
if [[ $IS_AMD64 -eq 0 ]]; then
  mark "pgAdmin4" SKIP "amd64-only (current arch: $ARCH)"
elif dpkg -s pgadmin4-desktop >/dev/null 2>&1; then
  mark "pgAdmin4" SKIP "already installed"
else
  if apt_get install -y pgadmin4-desktop; then
    mark "pgAdmin4" OK "installed (pgadmin4-desktop)"
  else
    mark "pgAdmin4" FAIL "install failed — codename '$CODENAME' may not be in pgAdmin repo yet"
  fi
fi

###############################################################################
# MODULE 3 — GOOGLE CHROME (official .deb, amd64-only)
###############################################################################
section "GOOGLE CHROME"
if [[ $IS_AMD64 -eq 0 ]]; then
  mark "Google Chrome" SKIP "amd64-only on Linux (current arch: $ARCH)"
elif have google-chrome || have google-chrome-stable; then
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
# MODULE 4 — MICROSOFT EDGE (official repo, amd64-only)
###############################################################################
section "MICROSOFT EDGE"
if [[ $IS_AMD64 -eq 0 ]]; then
  mark "Microsoft Edge" SKIP "amd64-only on Linux (current arch: $ARCH)"
elif have microsoft-edge || have microsoft-edge-stable; then
  mark "Microsoft Edge" SKIP "already installed"
else
  if apt_get install -y microsoft-edge-stable; then
    mark "Microsoft Edge" OK "installed (reads /etc/opt/edge/policies/managed/)"
  else
    mark "Microsoft Edge" FAIL "install failed — check repo/key in log"
  fi
fi

###############################################################################
# MODULE 5 — AZURE VPN CLIENT (Microsoft repo, amd64-only)
###############################################################################
section "AZURE VPN CLIENT"
if [[ $IS_AMD64 -eq 0 ]]; then
  mark "Azure VPN Client" SKIP "amd64-only (current arch: $ARCH)"
elif dpkg -s microsoft-azurevpnclient >/dev/null 2>&1; then
  mark "Azure VPN Client" SKIP "already installed"
else
  if apt_get install -y microsoft-azurevpnclient; then
    mark "Azure VPN Client" OK "installed"
  else
    mark "Azure VPN Client" FAIL "install failed — check apt log (jammy pool, amd64-only)"
  fi
fi

###############################################################################
# MODULE 6 — DOCKER DESKTOP (.deb + repo deps, amd64-only)
###############################################################################
section "DOCKER DESKTOP"
if [[ $IS_AMD64 -eq 0 ]]; then
  mark "Docker Desktop" SKIP "amd64-only on Linux (current arch: $ARCH)"
elif dpkg -s docker-desktop >/dev/null 2>&1; then
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
# MODULE 7 — kubectl + Minikube (direct binaries, arch-portable)
###############################################################################
section "kubectl + MINIKUBE"

# kubectl
if have kubectl; then
  mark "kubectl" SKIP "already installed"
else
  KVER="$(curl -L -s https://dl.k8s.io/release/stable.txt 2>/dev/null)"
  if [[ -n "$KVER" ]] \
     && curl -fsSLo "$TMP_ROOT/kubectl" "https://dl.k8s.io/release/${KVER}/bin/linux/${MINIKUBE_ARCH}/kubectl" \
     && install -m 0755 "$TMP_ROOT/kubectl" /usr/local/bin/kubectl; then
    mark "kubectl" OK "installed ${KVER} (/usr/local/bin/kubectl)"
  else
    mark "kubectl" FAIL "download or install failed — check log"
  fi
fi

# Minikube  (binary only — 'minikube start' is runtime, not provisioning)
if have minikube; then
  mark "Minikube" SKIP "already installed"
else
  if curl -fsSLo "$TMP_ROOT/minikube" "${MINIKUBE_URL_BASE}-${MINIKUBE_ARCH}" \
     && install -m 0755 "$TMP_ROOT/minikube" /usr/local/bin/minikube; then
    mark "Minikube" OK "installed (/usr/local/bin/minikube)"
  else
    mark "Minikube" FAIL "download or install failed — check log"
  fi
fi

###############################################################################
# MODULE 8 — DR. SPRINTO (AppImage)
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
# MODULE 9 — JETBRAINS: PyCharm (direct) + Toolbox (staged), arch-aware
###############################################################################
section "JETBRAINS PYCHARM + TOOLBOX"
PYCHARM_URL="${JB_DOWNLOAD_BASE}?code=PCP&platform=${JB_PLATFORM}"
TOOLBOX_URL="${JB_DOWNLOAD_BASE}?code=TBA&platform=${JB_PLATFORM}"
log "JetBrains platform code for this arch: $JB_PLATFORM"

# --- PyCharm direct to /opt ---
if [[ -d "$PYCHARM_DIR" ]] && [[ -n "$(ls -A "$PYCHARM_DIR" 2>/dev/null)" ]]; then
  mark "PyCharm" SKIP "already present ($PYCHARM_DIR)"
else
  pyc_tmp="$TMP_ROOT/pycharm"; mkdir -p "$pyc_tmp"
  log "Downloading PyCharm from $PYCHARM_URL"
  if curl -fSL "$PYCHARM_URL" -o "$pyc_tmp/pycharm.tar.gz" 2>>"$LOG_FILE" \
     && tar -xzf "$pyc_tmp/pycharm.tar.gz" -C "$pyc_tmp" 2>>"$LOG_FILE"; then
    # Find the extracted top-level directory (tarball has exactly one)
    src="$(find "$pyc_tmp" -mindepth 1 -maxdepth 1 -type d | head -n1)"
    if [[ -z "$src" ]]; then
      mark "PyCharm" FAIL "tarball extracted but no top-level directory found"
    else
      log "PyCharm extracted to: $src"
      rm -rf "$PYCHARM_DIR"; mv "$src" "$PYCHARM_DIR"

      # Find the launcher: try common names, then any pycharm* executable in bin/
      pyc_bin=""
      for cand in "$PYCHARM_DIR/bin/pycharm.sh" "$PYCHARM_DIR/bin/pycharm"; do
        [[ -f "$cand" ]] && { pyc_bin="$cand"; break; }
      done
      if [[ -z "$pyc_bin" ]] && [[ -d "$PYCHARM_DIR/bin" ]]; then
        pyc_bin="$(find "$PYCHARM_DIR/bin" -maxdepth 1 -type f \
                   \( -name 'pycharm*' -o -name 'PyCharm*' \) 2>/dev/null | head -n1)"
      fi

      if [[ -n "$pyc_bin" ]]; then
        chmod 0755 "$pyc_bin"
        ln -sf "$pyc_bin" /usr/local/bin/pycharm
        # Pick whichever icon file actually shipped
        pyc_icon=""
        for ic in pycharm.svg pycharm.png pycharm-professional.svg pycharm-professional.png; do
          [[ -f "$PYCHARM_DIR/bin/$ic" ]] && { pyc_icon="$PYCHARM_DIR/bin/$ic"; break; }
        done
        cat > /usr/share/applications/pycharm.desktop <<EOF
[Desktop Entry]
Name=PyCharm
Exec=$pyc_bin %f
Icon=${pyc_icon:-$PYCHARM_DIR/bin/pycharm.svg}
Type=Application
Categories=Development;IDE;
Terminal=false
StartupWMClass=jetbrains-pycharm
EOF
        mark "PyCharm" OK "installed ($PYCHARM_DIR -> $pyc_bin)"
      else
        # Dump bin/ contents so we can see what JetBrains actually shipped
        log "PyCharm bin/ contents:"
        ls -la "$PYCHARM_DIR/bin" 2>>"$LOG_FILE" >>"$LOG_FILE"
        mark "PyCharm" FAIL "extracted to $PYCHARM_DIR but no launcher found in bin/ (see log)"
      fi
    fi
  else
    mark "PyCharm" FAIL "download or extract failed — check log"
  fi
fi

# --- JetBrains Toolbox (staged binary, per-user GUI for IDE version mgmt) ---
if [[ -d "$TOOLBOX_DIR" ]] && [[ -n "$(ls -A "$TOOLBOX_DIR" 2>/dev/null)" ]]; then
  mark "JetBrains Toolbox" SKIP "already present ($TOOLBOX_DIR)"
else
  tb_tmp="$TMP_ROOT/toolbox"; mkdir -p "$tb_tmp"
  log "Downloading JetBrains Toolbox from $TOOLBOX_URL"
  if curl -fSL "$TOOLBOX_URL" -o "$tb_tmp/toolbox.tar.gz" 2>>"$LOG_FILE" \
     && tar -xzf "$tb_tmp/toolbox.tar.gz" -C "$tb_tmp" 2>>"$LOG_FILE"; then
    src="$(find "$tb_tmp" -mindepth 1 -maxdepth 1 -type d | head -n1)"
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
      mark "JetBrains Toolbox" FAIL "no top-level directory after extract"
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
log "RESULTS — OK:$ok  SKIP:$skip  FAIL:$fail   (arch: $ARCH)"
log "Log:     $LOG_FILE"
log "Summary: $SUMMARY_FILE"
log ""
log "Chrome + Edge (when installed) read policy from"
log "  /etc/opt/chrome/policies/managed/  and  /etc/opt/edge/policies/managed/"
log "so the extension block/allowlist policy applies once that script runs."
log ""
log "Run the MDM hardening policy AFTER this script (it locks down installs)."

# Exit 0 so a single optional-app failure doesn't fail the whole MDM job.
exit 0
