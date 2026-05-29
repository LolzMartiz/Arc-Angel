#!/usr/bin/env bash
###############################################################################
# AltiusHub — Standard App Provisioning Script v1
# -----------------------------------------------------------------------------
# Target: Debian / Ubuntu (Ubuntu 22.04 / 24.04 tested)
# Run as: root
# Push via: Scalefusion script job, or cron, or one-shot fetch
#
# Per-app behavior:
#   - Idempotent (re-running skips already-installed apps)
#   - Each app is a function — easy to enable/disable
#   - Failure of one app NEVER stops the rest
#   - Final summary table: OK / SKIP / FAIL / MANUAL / N/A
#
# Logs to: /var/log/altiushub-apps-install.log
#
# Manual / dashboard-gated apps deferred to v2:
#   - Dr. Sprinto (per-tenant download from sprinto.com dashboard)
#
# Not-on-Linux apps (per client decision):
#   - WSL, MS Office native, MobaXterm  -> reported as N/A
###############################################################################

set -uo pipefail   # NOT -e — we want soft failures so one bad app doesn't kill the rest

# ---------- Globals ---------------------------------------------------------
LOG_FILE="/var/log/altiushub-apps-install.log"
SUMMARY_FILE="/tmp/altiushub-install-summary.txt"
ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
CODENAME=$(. /etc/os-release && echo "${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}")
DISTRO_ID=$(. /etc/os-release && echo "$ID")

declare -A RESULT   # app_name -> OK|SKIP|FAIL|MANUAL|N/A
declare -A DETAIL   # app_name -> human-readable note

# ---------- Pretty logging --------------------------------------------------
log() { printf '[%(%F %T)T] %s\n' -1 "$*" | tee -a "$LOG_FILE"; }
section() { log ""; log "================================================================"; log "  $*"; log "================================================================"; }

mark() {
  # mark <app> <status> <detail>
  RESULT["$1"]="$2"
  DETAIL["$1"]="$3"
  log "[$2] $1 — $3"
}

# ---------- Preflight -------------------------------------------------------
preflight() {
  section "PREFLIGHT"
  [[ $EUID -eq 0 ]] || { echo "Must be run as root."; exit 1; }
  mkdir -p "$(dirname "$LOG_FILE")"; touch "$LOG_FILE"; chmod 600 "$LOG_FILE"

  log "Host: $(hostname)"
  log "Distro: $DISTRO_ID  Codename: $CODENAME  Arch: $ARCH"
  log "Kernel: $(uname -r)"

  if ! ping -c1 -W3 8.8.8.8 >/dev/null 2>&1; then
    log "FATAL: no internet connectivity"
    exit 2
  fi

  log "Disk free: $(df -h / | awk 'NR==2 {print $4}')"

  export DEBIAN_FRONTEND=noninteractive
  log "Updating package indexes..."
  apt-get update -y >/dev/null 2>&1 || log "WARN: apt-get update had non-zero exit (continuing)"

  log "Installing baseline tools (curl, wget, gnupg, ca-certificates, apt-transport-https)..."
  apt-get install -y curl wget gnupg ca-certificates apt-transport-https \
    software-properties-common lsb-release >>"$LOG_FILE" 2>&1 \
    || log "WARN: baseline tool install had non-zero exit"
}

# ---------- Helpers ---------------------------------------------------------
have_cmd()    { command -v "$1" >/dev/null 2>&1; }
have_pkg()    { dpkg -s "$1" >/dev/null 2>&1; }
have_snap()   { snap list "$1" >/dev/null 2>&1; }

ensure_snapd() {
  have_cmd snap && return 0
  log "Installing snapd..."
  apt-get install -y snapd >>"$LOG_FILE" 2>&1 || return 1
  systemctl enable --now snapd.socket >>"$LOG_FILE" 2>&1
  sleep 3
}

add_apt_repo() {
  # add_apt_repo <name> <key_url> <repo_line>
  local name="$1" key_url="$2" repo_line="$3"
  local key_path="/etc/apt/keyrings/${name}.gpg"
  local list_path="/etc/apt/sources.list.d/${name}.list"

  mkdir -p /etc/apt/keyrings
  if [[ ! -f "$key_path" ]]; then
    curl -fsSL "$key_url" | gpg --dearmor -o "$key_path" 2>>"$LOG_FILE" || return 1
    chmod 644 "$key_path"
  fi
  echo "$repo_line" > "$list_path"
  apt-get update -y >>"$LOG_FILE" 2>&1 || true
}

install_deb_url() {
  # install_deb_url <app_label> <url>
  local label="$1" url="$2"
  local tmpfile
  tmpfile=$(mktemp --suffix=.deb)
  if ! curl -fsSL "$url" -o "$tmpfile"; then
    rm -f "$tmpfile"; return 1
  fi
  apt-get install -y "$tmpfile" >>"$LOG_FILE" 2>&1
  local rc=$?
  rm -f "$tmpfile"
  return $rc
}

###############################################################################
# Per-app functions — each is independent
###############################################################################

install_vscode() {
  local NAME="VS Code"
  have_cmd code && { mark "$NAME" SKIP "already installed: $(code --version 2>/dev/null | head -1)"; return; }

  add_apt_repo "microsoft-vscode" \
    "https://packages.microsoft.com/keys/microsoft.asc" \
    "deb [arch=$ARCH signed-by=/etc/apt/keyrings/microsoft-vscode.gpg] https://packages.microsoft.com/repos/code stable main" \
    || { mark "$NAME" FAIL "repo setup failed"; return; }

  if apt-get install -y code >>"$LOG_FILE" 2>&1; then
    mark "$NAME" OK "$(code --version 2>/dev/null | head -1)"
  else
    mark "$NAME" FAIL "apt install failed"
  fi
}

install_docker() {
  local NAME="Docker Engine"
  # Note: "Docker Desktop" on Linux is a separate GUI tool. Most teams want Docker Engine.
  # If true Docker Desktop is required, swap this for the docker-desktop .deb.
  have_cmd docker && { mark "$NAME" SKIP "already installed: $(docker --version 2>/dev/null)"; return; }

  add_apt_repo "docker" \
    "https://download.docker.com/linux/${DISTRO_ID}/gpg" \
    "deb [arch=$ARCH signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${DISTRO_ID} $CODENAME stable" \
    || { mark "$NAME" FAIL "repo setup failed"; return; }

  if apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >>"$LOG_FILE" 2>&1; then
    systemctl enable --now docker >>"$LOG_FILE" 2>&1
    mark "$NAME" OK "$(docker --version 2>/dev/null)"
  else
    mark "$NAME" FAIL "apt install failed"
  fi
}

install_minikube() {
  local NAME="Minikube"
  have_cmd minikube && { mark "$NAME" SKIP "already installed: $(minikube version --short 2>/dev/null)"; return; }

  local url="https://storage.googleapis.com/minikube/releases/latest/minikube_latest_${ARCH}.deb"
  if install_deb_url "$NAME" "$url"; then
    mark "$NAME" OK "$(minikube version --short 2>/dev/null || echo installed)"
  else
    mark "$NAME" FAIL "download or install failed"
  fi
}

install_postman() {
  local NAME="Postman"
  have_snap postman && { mark "$NAME" SKIP "snap already installed"; return; }
  ensure_snapd || { mark "$NAME" FAIL "snapd unavailable"; return; }

  if snap install postman >>"$LOG_FILE" 2>&1; then
    mark "$NAME" OK "snap installed"
  else
    mark "$NAME" FAIL "snap install failed"
  fi
}

install_cryptopro() {
  local NAME="CryptoPro"
  have_snap cryptopro && { mark "$NAME" SKIP "snap already installed"; return; }
  ensure_snapd || { mark "$NAME" FAIL "snapd unavailable"; return; }

  if snap install cryptopro --edge >>"$LOG_FILE" 2>&1; then
    mark "$NAME" OK "snap (edge channel) installed"
  else
    mark "$NAME" FAIL "snap install failed — check snapcraft.io/cryptopro"
  fi
}

install_chrome() {
  local NAME="Google Chrome"
  have_pkg google-chrome-stable && { mark "$NAME" SKIP "already installed"; return; }

  local url="https://dl.google.com/linux/direct/google-chrome-stable_current_${ARCH}.deb"
  if install_deb_url "$NAME" "$url"; then
    mark "$NAME" OK "$(google-chrome --version 2>/dev/null || echo installed)"
  else
    mark "$NAME" FAIL "download or install failed"
  fi
}

install_edge() {
  local NAME="Microsoft Edge"
  have_pkg microsoft-edge-stable && { mark "$NAME" SKIP "already installed"; return; }

  add_apt_repo "microsoft-edge" \
    "https://packages.microsoft.com/keys/microsoft.asc" \
    "deb [arch=$ARCH signed-by=/etc/apt/keyrings/microsoft-edge.gpg] https://packages.microsoft.com/repos/edge stable main" \
    || { mark "$NAME" FAIL "repo setup failed"; return; }

  if apt-get install -y microsoft-edge-stable >>"$LOG_FILE" 2>&1; then
    mark "$NAME" OK "$(microsoft-edge --version 2>/dev/null || echo installed)"
  else
    mark "$NAME" FAIL "apt install failed"
  fi
}

install_pgadmin4() {
  local NAME="pgAdmin 4"
  have_pkg pgadmin4-desktop && { mark "$NAME" SKIP "already installed"; return; }

  curl -fsSL https://www.pgadmin.org/static/packages_pgadmin_org.pub | \
    gpg --dearmor -o /etc/apt/keyrings/packages-pgadmin-org.gpg 2>>"$LOG_FILE"

  echo "deb [signed-by=/etc/apt/keyrings/packages-pgadmin-org.gpg] https://ftp.postgresql.org/pub/pgadmin/pgadmin4/apt/$CODENAME pgadmin4 main" \
    > /etc/apt/sources.list.d/pgadmin4.list

  apt-get update -y >>"$LOG_FILE" 2>&1
  if apt-get install -y pgadmin4-desktop >>"$LOG_FILE" 2>&1; then
    mark "$NAME" OK "installed"
  else
    mark "$NAME" FAIL "apt install failed (codename '$CODENAME' may be unsupported)"
  fi
}

install_dbeaver() {
  local NAME="DBeaver CE"
  have_pkg dbeaver-ce && { mark "$NAME" SKIP "already installed"; return; }

  local url="https://dbeaver.io/files/dbeaver-ce_latest_${ARCH}.deb"
  if install_deb_url "$NAME" "$url"; then
    mark "$NAME" OK "installed"
  else
    mark "$NAME" FAIL "download or install failed"
  fi
}

install_drawio() {
  local NAME="draw.io"
  have_pkg drawio && { mark "$NAME" SKIP "already installed"; return; }

  # Fetch latest .deb URL from GitHub releases API
  local url
  url=$(curl -fsSL https://api.github.com/repos/jgraph/drawio-desktop/releases/latest \
        | grep -E "browser_download_url.*${ARCH}\.deb" | head -1 | cut -d '"' -f 4)

  if [[ -z "$url" ]]; then
    mark "$NAME" FAIL "could not find latest .deb URL"
    return
  fi

  if install_deb_url "$NAME" "$url"; then
    mark "$NAME" OK "installed"
  else
    mark "$NAME" FAIL "download or install failed"
  fi
}

install_remmina() {
  # MobaXterm doesn't exist on Linux — Remmina is the standard substitute
  local NAME="Remmina (MobaXterm substitute)"
  have_pkg remmina && { mark "$NAME" SKIP "already installed"; return; }

  if apt-get install -y remmina remmina-plugin-rdp remmina-plugin-vnc remmina-plugin-secret >>"$LOG_FILE" 2>&1; then
    mark "$NAME" OK "installed"
  else
    mark "$NAME" FAIL "apt install failed"
  fi
}

install_azure_vpn() {
  local NAME="Azure VPN Client"
  have_pkg microsoft-azurevpnclient && { mark "$NAME" SKIP "already installed"; return; }

  # Only Ubuntu 22.04 and 24.04 are supported by Microsoft.
  case "$CODENAME" in
    jammy|noble)
      add_apt_repo "microsoft-prod" \
        "https://packages.microsoft.com/keys/microsoft.asc" \
        "deb [arch=$ARCH signed-by=/etc/apt/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/ubuntu/${CODENAME#jammy}${CODENAME:+22.04}/prod $CODENAME main"

      # The above codename hack is messy; just use Microsoft's standard prod repo per release:
      rm -f /etc/apt/sources.list.d/microsoft-prod.list
      if [[ "$CODENAME" == "jammy" ]]; then
        echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/ubuntu/22.04/prod jammy main" > /etc/apt/sources.list.d/microsoft-prod.list
      else
        echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/ubuntu/24.04/prod noble main" > /etc/apt/sources.list.d/microsoft-prod.list
      fi
      apt-get update -y >>"$LOG_FILE" 2>&1

      if apt-get install -y microsoft-azurevpnclient >>"$LOG_FILE" 2>&1; then
        mark "$NAME" OK "installed (note: MS announced retirement Aug 31, 2026)"
      else
        mark "$NAME" FAIL "apt install failed"
      fi
      ;;
    *)
      mark "$NAME" MANUAL "Microsoft only supports Ubuntu 22.04/24.04 — use strongSwan IKEv2 here"
      ;;
  esac
}

install_zed() {
  local NAME="Zed IDE"
  have_cmd zed && { mark "$NAME" SKIP "already installed"; return; }

  # Zed's official installer is per-user; for a system-wide multi-user install we use
  # the community-maintained Debian repo from debian.griffo.io
  add_apt_repo "zed-griffo" \
    "https://debian.griffo.io/EA0F721D231FDD3A0A17B9AC7808B4DD62C41256.asc" \
    "deb [arch=$ARCH signed-by=/etc/apt/keyrings/zed-griffo.gpg] https://debian.griffo.io/apt $CODENAME main" \
    || { mark "$NAME" FAIL "repo setup failed"; return; }

  if apt-get install -y zed >>"$LOG_FILE" 2>&1; then
    mark "$NAME" OK "installed (community .deb)"
  else
    mark "$NAME" FAIL "apt install failed — codename '$CODENAME' may be unsupported"
  fi
}

install_github_desktop() {
  local NAME="GitHub Desktop"
  have_pkg github-desktop && { mark "$NAME" SKIP "already installed"; return; }

  # GitHub Inc. doesn't ship a Linux build. Using shiftkey community fork.
  add_apt_repo "shiftkey-desktop" \
    "https://apt.packages.shiftkey.dev/gpg.key" \
    "deb [arch=$ARCH signed-by=/etc/apt/keyrings/shiftkey-desktop.gpg] https://apt.packages.shiftkey.dev/ubuntu/ any main" \
    || { mark "$NAME" FAIL "repo setup failed"; return; }

  if apt-get install -y github-desktop >>"$LOG_FILE" 2>&1; then
    mark "$NAME" OK "installed (shiftkey community fork)"
  else
    mark "$NAME" FAIL "apt install failed"
  fi
}

install_pycharm() {
  local NAME="PyCharm Community"
  have_snap pycharm-community && { mark "$NAME" SKIP "already installed"; return; }
  ensure_snapd || { mark "$NAME" FAIL "snapd unavailable"; return; }

  # Use --classic for IDE access to the full filesystem
  if snap install pycharm-community --classic >>"$LOG_FILE" 2>&1; then
    mark "$NAME" OK "snap (classic) installed"
  else
    mark "$NAME" FAIL "snap install failed"
  fi
}

install_libreoffice() {
  # MS Office substitute per client decision
  local NAME="LibreOffice (MS Office substitute)"
  have_pkg libreoffice && { mark "$NAME" SKIP "already installed"; return; }

  if apt-get install -y libreoffice >>"$LOG_FILE" 2>&1; then
    mark "$NAME" OK "installed"
  else
    mark "$NAME" FAIL "apt install failed"
  fi
}

# ---------- Not-on-Linux apps -----------------------------------------------
mark_not_on_linux() {
  mark "WSL"               N/A "Windows-only feature, no Linux equivalent needed"
  mark "MS Office native"  N/A "no native Linux build — LibreOffice installed as substitute"
  mark "MobaXterm"         N/A "Windows-only — Remmina installed as substitute"
  mark "Dr. Sprinto"       MANUAL "dashboard-gated; deferred to v2 with internal share"
}

###############################################################################
# Main
###############################################################################
main() {
  preflight

  section "INSTALLING APPLICATIONS"
  install_vscode
  install_docker
  install_minikube
  install_postman
  install_cryptopro
  install_chrome
  install_edge
  install_pgadmin4
  install_dbeaver
  install_drawio
  install_remmina
  install_azure_vpn
  install_zed
  install_github_desktop
  install_pycharm
  install_libreoffice
  mark_not_on_linux

  section "SUMMARY"
  {
    printf '\n%-35s %-8s %s\n' "APPLICATION" "STATUS" "DETAIL"
    printf '%-35s %-8s %s\n' "-----------" "------" "------"
    for app in "${!RESULT[@]}"; do
      printf '%-35s %-8s %s\n' "$app" "${RESULT[$app]}" "${DETAIL[$app]}"
    done | sort
  } | tee "$SUMMARY_FILE" | tee -a "$LOG_FILE"

  # Counts
  local ok=0 fail=0 skip=0 manual=0 na=0
  for s in "${RESULT[@]}"; do
    case "$s" in
      OK) ((ok++));; FAIL) ((fail++));; SKIP) ((skip++));;
      MANUAL) ((manual++));; N/A) ((na++));;
    esac
  done

  log ""
  log "RESULT COUNTS — OK:$ok  SKIP:$skip  FAIL:$fail  MANUAL:$manual  N/A:$na"
  log "Full log: $LOG_FILE"
  log "Summary:  $SUMMARY_FILE"

  # Exit code: 0 if no failures, 1 otherwise (Scalefusion can read this)
  [[ $fail -eq 0 ]] && exit 0 || exit 1
}

main "$@"
