#!/usr/bin/env bash
###############################################################################
# AltiusHub — Flatpak App Provisioning Script
# -----------------------------------------------------------------------------
# Target: Debian / Ubuntu
# Run as: root
# Push via: Scalefusion script job (or detached one-shot fetch)
#
# What it does:
#   1. Installs Flatpak runtime if missing
#   2. Adds the Flathub remote
#   3. Installs the curated app list (only apps that genuinely exist on Flathub)
#   4. Idempotent — skips already-installed apps
#   5. Soft failures — one bad app doesn't stop the rest
#   6. Status table at the end
#
# Log:     /var/log/altiushub-flatpak-install.log
# Summary: /tmp/altiushub-flatpak-summary.txt
###############################################################################

set -uo pipefail

LOG_FILE="/var/log/altiushub-flatpak-install.log"
SUMMARY_FILE="/tmp/altiushub-flatpak-summary.txt"

declare -A RESULT
declare -A DETAIL

log() { printf '[%(%F %T)T] %s\n' -1 "$*" | tee -a "$LOG_FILE"; }
section() { log ""; log "================================================================"; log "  $*"; log "================================================================"; }
mark() { RESULT["$1"]="$2"; DETAIL["$1"]="$3"; log "[$2] $1 — $3"; }

# ---------- The curated Flathub app list ------------------------------------
# Only apps that genuinely have working Flathub packages.
# Format: "Friendly Name|flathub.app.id"
APPS=(
  "VS Code|com.visualstudio.code"
  "Postman|com.getpostman.Postman"
  "draw.io|com.jgraph.drawio.desktop"
  "DBeaver CE|io.dbeaver.DBeaverCommunity"
  "GitHub Desktop|io.github.shiftey.Desktop"
  "Zed IDE|dev.zed.Zed"
  "LibreOffice|org.libreoffice.LibreOffice"
)

# ---------- Preflight -------------------------------------------------------
[[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }
mkdir -p "$(dirname "$LOG_FILE")"; touch "$LOG_FILE"; chmod 600 "$LOG_FILE"

section "PREFLIGHT"
log "Host: $(hostname)"
log "OS:   $(. /etc/os-release && echo "$PRETTY_NAME")"

if ! ping -c1 -W3 8.8.8.8 >/dev/null 2>&1; then
  log "FATAL: no internet"; exit 2
fi

export DEBIAN_FRONTEND=noninteractive

# ---------- Install flatpak runtime -----------------------------------------
section "INSTALL FLATPAK RUNTIME"
if command -v flatpak >/dev/null 2>&1; then
  log "flatpak already installed: $(flatpak --version)"
else
  log "Installing flatpak..."
  if apt-get update -y >>"$LOG_FILE" 2>&1 && \
     apt-get install -y flatpak >>"$LOG_FILE" 2>&1; then
    log "flatpak installed: $(flatpak --version)"
  else
    log "FATAL: flatpak install failed. Check $LOG_FILE for apt errors."
    exit 3
  fi
fi

# ---------- Add Flathub remote ----------------------------------------------
section "CONFIGURE FLATHUB REMOTE"
if flatpak remote-list --system 2>/dev/null | grep -q '^flathub'; then
  log "Flathub remote already configured."
else
  log "Adding Flathub remote (system-wide)..."
  flatpak remote-add --system --if-not-exists flathub \
    https://flathub.org/repo/flathub.flatpakrepo >>"$LOG_FILE" 2>&1
  log "Flathub remote added."
fi

# ---------- Install apps ----------------------------------------------------
section "INSTALL APPS"
for entry in "${APPS[@]}"; do
  name="${entry%%|*}"
  appid="${entry##*|}"

  # Skip if already installed
  if flatpak list --system --app --columns=application 2>/dev/null | grep -qx "$appid"; then
    mark "$name" SKIP "already installed ($appid)"
    continue
  fi

  log "Installing $name ($appid)..."
  if flatpak install -y --system --noninteractive flathub "$appid" >>"$LOG_FILE" 2>&1; then
    mark "$name" OK "installed"
  else
    mark "$name" FAIL "flatpak install failed — check log"
  fi
done

# ---------- Summary ---------------------------------------------------------
section "SUMMARY"
{
  printf '\n%-25s %-8s %s\n' "APPLICATION" "STATUS" "DETAIL"
  printf '%-25s %-8s %s\n'   "-----------" "------" "------"
  for app in "${!RESULT[@]}"; do
    printf '%-25s %-8s %s\n' "$app" "${RESULT[$app]}" "${DETAIL[$app]}"
  done | sort
} | tee "$SUMMARY_FILE" | tee -a "$LOG_FILE"

ok=0; fail=0; skip=0
for s in "${RESULT[@]}"; do
  case "$s" in OK) ((ok++));; FAIL) ((fail++));; SKIP) ((skip++));; esac
done

log ""
log "RESULTS — OK:$ok  SKIP:$skip  FAIL:$fail"
log "Log:     $LOG_FILE"
log "Summary: $SUMMARY_FILE"
log ""
log "NOTE: Apps not on Flathub (Chrome, Edge, pgAdmin, Docker, Minikube,"
log "      PyCharm, CryptoPro, Dr. Sprinto, Azure VPN) must be installed"
log "      via the apt/snap script or client-provided commands."

[[ $fail -eq 0 ]] && exit 0 || exit 1
