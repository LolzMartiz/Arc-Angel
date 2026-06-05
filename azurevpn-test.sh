#!/usr/bin/env bash
###############################################################################
# AltiusHub — Azure VPN Client install TEST  (standalone)
# -----------------------------------------------------------------------------
# Microsoft only ships microsoft-azurevpnclient for Ubuntu 20.04 (focal) and
# 22.04 (jammy). On 24.04 (noble) the package isn't in the noble prod repo,
# which is why our main script's install fails with "Unable to locate package".
#
# This script tries 3 strategies on your noble box, in order, until one works:
#   1. Add Microsoft's JAMMY prod repo (instead of noble) and apt install.
#   2. If apt install fails on dependencies, download the .deb directly from
#      the jammy pool and force-install with `apt install ./deb` so apt can
#      resolve deps against noble's library versions.
#   3. If that also fails, dump the exact missing dependencies for inspection.
#
# Run as: root  ->  sudo bash azurevpn-test.sh
#
# This is a TEST. It only adds/removes its own /etc/apt/sources.list.d/ files
# and only installs microsoft-azurevpnclient (or attempts to).
# Log:    /var/log/azurevpn-test.log
###############################################################################

set -uo pipefail

LOG_FILE="/var/log/azurevpn-test.log"
KEYRING="/usr/share/keyrings/microsoft-prod.gpg"
LIST_FILE="/etc/apt/sources.list.d/microsoft-azurevpn-jammy.list"
MS_KEY_URL="https://packages.microsoft.com/keys/microsoft.asc"
JAMMY_REPO_URL="https://packages.microsoft.com/ubuntu/22.04/prod"

mkdir -p "$(dirname "$LOG_FILE")"; touch "$LOG_FILE"; chmod 600 "$LOG_FILE"

log() { printf '[%(%F %T)T] %s\n' -1 "$*" | tee -a "$LOG_FILE"; }
section() { log ""; log "================================================================"; log "  $*"; log "================================================================"; }

[[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }

section "PREFLIGHT"
. /etc/os-release
log "Host:    $(hostname)"
log "Distro:  ${PRETTY_NAME}"
log "Codename: ${VERSION_CODENAME:-?}"
log "Arch:    $(dpkg --print-architecture)"

if [[ "$(dpkg --print-architecture)" != "amd64" ]]; then
  log "FATAL: Azure VPN Client is amd64-only on Linux. Stopping."
  exit 2
fi

# Check if it's already installed
if dpkg -s microsoft-azurevpnclient >/dev/null 2>&1; then
  log "microsoft-azurevpnclient already installed:"
  dpkg -s microsoft-azurevpnclient | grep -E 'Version|Status' | tee -a "$LOG_FILE"
  exit 0
fi

###############################################################################
# STRATEGY 1 — Add jammy prod repo, apt install
###############################################################################
section "STRATEGY 1 — jammy repo + apt install"

# Microsoft signing key (idempotent)
install -d -m 0755 /usr/share/keyrings
if [[ ! -s "$KEYRING" ]]; then
  log "Fetching Microsoft signing key..."
  if curl -fsSL "$MS_KEY_URL" | gpg --dearmor --yes -o "$KEYRING" 2>>"$LOG_FILE"; then
    log "Key installed -> $KEYRING"
  else
    log "FATAL: failed to fetch/install Microsoft key"
    exit 3
  fi
else
  log "Microsoft key already present at $KEYRING"
fi

# Point at JAMMY pool specifically, not noble
log "Writing jammy repo list -> $LIST_FILE"
echo "deb [arch=amd64 signed-by=${KEYRING}] ${JAMMY_REPO_URL} jammy main" > "$LIST_FILE"
cat "$LIST_FILE" | tee -a "$LOG_FILE"

log "Refreshing apt..."
DEBIAN_FRONTEND=noninteractive apt-get update >>"$LOG_FILE" 2>&1 \
  || log "apt update reported errors (continuing)"

log "Searching apt cache for microsoft-azurevpnclient..."
apt-cache policy microsoft-azurevpnclient | tee -a "$LOG_FILE"

log "Attempting: apt-get install -y microsoft-azurevpnclient"
if DEBIAN_FRONTEND=noninteractive apt-get install -y microsoft-azurevpnclient >>"$LOG_FILE" 2>&1; then
  log "[OK] STRATEGY 1 worked — installed via jammy apt repo."
  dpkg -s microsoft-azurevpnclient | grep -E 'Package|Version' | tee -a "$LOG_FILE"
  log ""
  log "Launch the GUI with: azurevpn"
  exit 0
fi

log "STRATEGY 1 failed — trying direct .deb fetch."
log "----- apt error tail: -----"
tail -n 30 "$LOG_FILE" | sed -n '/microsoft-azurevpnclient/,$p' | tee -a "$LOG_FILE"

###############################################################################
# STRATEGY 2 — Download the .deb directly from jammy pool, let apt resolve
###############################################################################
section "STRATEGY 2 — direct .deb fetch from jammy pool"

# Find the latest .deb in the jammy pool listing
POOL_INDEX="${JAMMY_REPO_URL}/pool/main/m/microsoft-azurevpnclient/"
log "Listing pool: $POOL_INDEX"
DEB_NAME="$(curl -fsSL "$POOL_INDEX" 2>>"$LOG_FILE" \
  | grep -oE 'microsoft-azurevpnclient_[^"]+_amd64\.deb' \
  | sort -V | tail -n1)"

if [[ -z "$DEB_NAME" ]]; then
  log "FATAL: could not find a .deb in the jammy pool listing."
  log "Manual fallback: browse $POOL_INDEX in a browser and download the latest .deb."
  exit 4
fi

log "Latest jammy .deb: $DEB_NAME"
TMP_DEB="/tmp/${DEB_NAME}"
log "Downloading -> $TMP_DEB"
if ! curl -fSL "${POOL_INDEX}${DEB_NAME}" -o "$TMP_DEB" 2>>"$LOG_FILE"; then
  log "FATAL: download failed."
  exit 5
fi
log "Downloaded $(du -h "$TMP_DEB" | awk '{print $1}')"

log "Attempting: apt-get install -y $TMP_DEB"
if DEBIAN_FRONTEND=noninteractive apt-get install -y "$TMP_DEB" >>"$LOG_FILE" 2>&1; then
  log "[OK] STRATEGY 2 worked — installed via direct .deb."
  dpkg -s microsoft-azurevpnclient | grep -E 'Package|Version' | tee -a "$LOG_FILE"
  log ""
  log "Launch the GUI with: azurevpn"
  exit 0
fi

###############################################################################
# STRATEGY 3 — Diagnose what's missing
###############################################################################
section "STRATEGY 3 — diagnose missing dependencies"

log "Inspecting .deb dependencies..."
dpkg -I "$TMP_DEB" 2>/dev/null | grep -E '^ (Depends|Pre-Depends|Recommends):' | tee -a "$LOG_FILE"

log ""
log "Checking each dep against noble's apt cache..."
deps="$(dpkg -I "$TMP_DEB" 2>/dev/null | awk -F': ' '/^ Depends:/ {print $2}' | tr ',' '\n' | sed 's/^ *//;s/ .*//')"
missing=()
for dep in $deps; do
  [[ -z "$dep" ]] && continue
  if apt-cache show "$dep" >/dev/null 2>&1; then
    log "  OK     : $dep"
  else
    log "  MISSING: $dep"
    missing+=("$dep")
  fi
done

log ""
if [[ ${#missing[@]} -eq 0 ]]; then
  log "All declared deps exist in apt cache — the failure must be a version constraint."
  log "Run this for the full version-level reason:"
  log "  apt-get install -y $TMP_DEB"
else
  log "Missing on noble: ${missing[*]}"
  log "These libraries either have new names on noble (e.g. libssl3 -> libssl3t64)"
  log "or aren't available. Microsoft hasn't built this package for 24.04."
fi

log ""
log "[FAIL] microsoft-azurevpnclient could not be installed on this host."
log "Full log: $LOG_FILE"
exit 6
