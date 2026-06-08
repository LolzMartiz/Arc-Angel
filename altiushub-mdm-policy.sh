#!/usr/bin/env bash
###############################################################################
# AltiusHub — Unified MDM Deployment Policy
# -----------------------------------------------------------------------------
# Target:   Debian / Debian-based (Ubuntu, Mint, etc.)
# Run as:   root   ->   sudo bash altiushub-mdm-policy.sh
# Push via: Scalefusion script job (fetch + run, one shot)
#
# This single policy applies three validated modules, in order:
#   MODULE 1  Endpoint hardening
#             - Create/refresh the 'AltiusHub' admin user (fixed fleet password)
#             - Verify it can authenticate + sudo BEFORE touching anyone (lockout guard)
#             - Demote all other sudoers/admins to standard users
#             - Block GUI installs (polkit) and CLI installs (apt/dpkg/snap/flatpak)
#             - Disable Bluetooth (service + kernel module + rfkill)
#   MODULE 2  Browser extension control (Chrome + Edge)
#             - Block every extension, allow only the approved IDs
#   MODULE 3  VS Code marketplace lockdown
#             - Disable the built-in extension gallery (extensions pushed via terminal)
#
# Flags:
#   --dry-run      Print actions, change nothing (works across all 3 modules)
#   --password X   Override the fleet admin password for this run only
#   --keep-user U  Keep this username as a sudoer too (besides AltiusHub)
#
# Log:          /var/log/altiushub-mdm-policy.log
# Credentials:  /root/altiushub-credentials.txt   (root-readable only)
###############################################################################

set -uo pipefail

# ============================ CONFIG =========================================
ADMIN_USER="AltiusHub"
# Fixed fleet password. Single quotes = stored literally (the # and ! are NOT
# interpreted by the shell).
FLEET_PASSWORD='AltiusHub_Admin#84!Zq'

LOG_FILE="/var/log/altiushub-mdm-policy.log"
CRED_FILE="/root/altiushub-credentials.txt"

DRY_RUN=0
CUSTOM_PASSWORD=""
KEEP_USER=""

# --- Browser policy targets ---
CHROME_MANAGED_DIR="/etc/opt/chrome/policies/managed"
EDGE_MANAGED_DIR="/etc/opt/edge/policies/managed"
BROWSER_POLICY_FILE="block_extensions.json"

# Approved extension IDs, exactly as locked in during testing.
# Everything else is blocked by the "*" blocklist. Add IDs here to widen the
# allowlist later; re-run the policy to apply.
CHROME_ALLOWLIST='["iohjgamcilhbgmhbnllfolmkmmekfmci"]'
EDGE_ALLOWLIST='[
    "bojobppfploabceghnmlahpoonbcbacn",
    "cnlefmmeadmemmdciolhbnfeacpdfbkd",
    "iohjgamcilhbgmhbnllfolmkmmekfmci"
  ]'

# --- VS Code target ---
VSCODE_PRODUCT="/usr/share/code/resources/app/product.json"

# --- Module status (for the final summary) ---
STATUS_HARDEN="not run"
STATUS_BROWSER="not run"
STATUS_VSCODE="not run"

# ============================ ARG PARSING ====================================
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)   DRY_RUN=1; shift ;;
    --password)  CUSTOM_PASSWORD="$2"; shift 2 ;;
    --keep-user) KEEP_USER="$2"; shift 2 ;;
    -h|--help)
      cat <<'USAGE'
AltiusHub Unified MDM Deployment Policy
Usage: sudo bash altiushub-mdm-policy.sh [--dry-run] [--password X] [--keep-user U]
  --dry-run      Print actions, change nothing
  --password X   Override the fleet admin password for this run only
  --keep-user U  Keep this username as a sudoer too (besides AltiusHub)
USAGE
      exit 0 ;;
    *) echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

# ============================ HELPERS ========================================
log() {
  local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
  echo "$msg" | tee -a "$LOG_FILE"
}
section() {
  log ""
  log "================================================================"
  log "  $*"
  log "================================================================"
}
run() {
  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY-RUN: $*"
  else
    log "RUN: $*"
    eval "$@"
  fi
}
die() {
  log "FATAL: $*"
  log "Aborting. No destructive changes applied beyond this point."
  exit 1
}
require_root() { [[ $EUID -eq 0 ]] || die "This script must be run as root."; }

# ============================ PREFLIGHT ======================================
require_root
mkdir -p "$(dirname "$LOG_FILE")"; touch "$LOG_FILE"; chmod 600 "$LOG_FILE"

section "ALTIUSHUB MDM POLICY START  (dry-run=$DRY_RUN)"
log "Host:   $(hostname)"
log "Kernel: $(uname -r)"
log "OS:     $(. /etc/os-release && echo "$PRETTY_NAME")"

# Pick the password to use this run
if [[ -n "$CUSTOM_PASSWORD" ]]; then
  EFFECTIVE_PASSWORD="$CUSTOM_PASSWORD"
  log "Using operator-supplied password (--password)."
else
  EFFECTIVE_PASSWORD="$FLEET_PASSWORD"
  log "Using fixed fleet password."
fi

# Detect desktop environment (informational; rules below are universal)
DETECTED_DE="${XDG_CURRENT_DESKTOP:-}"
if [[ -z "$DETECTED_DE" ]]; then
  if   command -v gnome-shell   >/dev/null 2>&1; then DETECTED_DE="GNOME"
  elif command -v plasmashell   >/dev/null 2>&1; then DETECTED_DE="KDE"
  elif command -v xfce4-session >/dev/null 2>&1; then DETECTED_DE="XFCE"
  else DETECTED_DE="headless-or-unknown"; fi
fi
log "Desktop environment: $DETECTED_DE"

for bin in useradd usermod passwd getent systemctl; do
  command -v "$bin" >/dev/null 2>&1 || die "Required binary missing: $bin"
done

###############################################################################
# MODULE 1 — ENDPOINT HARDENING
###############################################################################
section "MODULE 1 — ENDPOINT HARDENING"

# ---- 1.1 Create / refresh admin user --------------------------------------
log "----- 1.1 Create admin user '$ADMIN_USER' -----"
if getent passwd "$ADMIN_USER" >/dev/null; then
  log "User '$ADMIN_USER' exists — resetting password and ensuring sudo group."
  if [[ $DRY_RUN -eq 0 ]]; then
    echo "${ADMIN_USER}:${EFFECTIVE_PASSWORD}" | chpasswd || die "Failed to set password for $ADMIN_USER"
    usermod -aG sudo "$ADMIN_USER" || die "Failed to add $ADMIN_USER to sudo group"
  fi
else
  if [[ $DRY_RUN -eq 0 ]]; then
    useradd -m -s /bin/bash -c "AltiusHub Administrator" "$ADMIN_USER" || die "useradd failed for $ADMIN_USER"
    echo "${ADMIN_USER}:${EFFECTIVE_PASSWORD}" | chpasswd || die "Failed to set password for $ADMIN_USER"
    usermod -aG sudo "$ADMIN_USER" || die "Failed to add $ADMIN_USER to sudo group"
  else
    log "DRY-RUN: would create $ADMIN_USER, set password, add to sudo group"
  fi
fi

# Save credentials to a root-only file.
# Subshell scopes the umask change so it can't leak into later modules
# (without this, Module 2's mkdir -p inherited 077 and created the policy
# dirs as 700 — Chrome couldn't traverse in and silently dropped the policy).
if [[ $DRY_RUN -eq 0 ]]; then
  (
    umask 077
    cat > "$CRED_FILE" <<EOF
AltiusHub admin credentials
Generated: $(date '+%Y-%m-%d %H:%M:%S')
Host:      $(hostname)
Username:  $ADMIN_USER
Password:  $EFFECTIVE_PASSWORD

Store this securely. This file is readable only by root.
EOF
    chmod 600 "$CRED_FILE"
  )
fi

# ---- 1.2 Verify auth + sudo (LOCKOUT GUARD) -------------------------------
log "----- 1.2 Verify '$ADMIN_USER' authentication and sudo access (lockout guard) -----"
if [[ $DRY_RUN -eq 0 ]]; then
  # Test 1: PAM authentication via su
  if ! echo "$EFFECTIVE_PASSWORD" | su -c "id" "$ADMIN_USER" >/dev/null 2>&1; then
    die "Cannot authenticate as $ADMIN_USER. Existing users' sudo is UNTOUCHED."
  fi
  log "PAM auth check passed."

  # Test 2: sudo group membership
  if ! id -nG "$ADMIN_USER" | grep -qw sudo; then
    die "$ADMIN_USER is not in 'sudo' group. Existing users' sudo is UNTOUCHED."
  fi
  log "Sudo group membership confirmed."
else
  log "DRY-RUN: skipping verification (no real user created)"
fi

# ---- 1.3 Demote other sudoers to standard users ---------------------------
log "----- 1.3 Demote other admin users to standard -----"
mapfile -t CURRENT_ADMINS < <(
  getent group sudo  | awk -F: '{print $4}' | tr ',' '\n'
  getent group admin | awk -F: '{print $4}' | tr ',' '\n' 2>/dev/null
  getent group wheel | awk -F: '{print $4}' | tr ',' '\n' 2>/dev/null
)

for u in "${CURRENT_ADMINS[@]}"; do
  [[ -z "$u" ]] && continue
  [[ "$u" == "$ADMIN_USER" ]] && continue
  [[ "$u" == "$KEEP_USER" ]] && continue
  [[ "$u" == "root" ]] && continue

  log "Removing '$u' from sudo/admin/wheel groups."
  run "gpasswd -d '$u' sudo 2>/dev/null || true"
  run "gpasswd -d '$u' admin 2>/dev/null || true"
  run "gpasswd -d '$u' wheel 2>/dev/null || true"
done

# Move aside any stray per-user sudoers.d files that might grant NOPASSWD
log "Scanning /etc/sudoers.d/ for stray entries..."
if [[ -d /etc/sudoers.d ]]; then
  for f in /etc/sudoers.d/*; do
    [[ -f "$f" ]] || continue
    [[ "$(basename "$f")" == "README" ]] && continue
    [[ "$(basename "$f")" == "altiushub" ]] && continue
    run "mv '$f' '${f}.disabled-$(date +%s)'"
  done
fi

# ---- 1.4 Block GUI installs (PolicyKit rules) -----------------------------
log "----- 1.4 Block GUI software installation -----"
POLKIT_RULES_DIR="/etc/polkit-1/rules.d"
POLKIT_LOCAL_DIR="/etc/polkit-1/localauthority/50-local.d"

if [[ -d "$POLKIT_RULES_DIR" ]]; then
  run "cat > '${POLKIT_RULES_DIR}/49-altiushub-block-installs.rules' <<'RULES'
// AltiusHub: require admin password for all package management actions
polkit.addRule(function(action, subject) {
    if (action.id.indexOf('org.freedesktop.packagekit.') === 0 ||
        action.id.indexOf('org.debian.apt.') === 0 ||
        action.id.indexOf('io.snapcraft.') === 0 ||
        action.id.indexOf('org.flatpak.') === 0) {
        return polkit.Result.AUTH_ADMIN_KEEP;
    }
});
RULES"
fi

# Older polkit (pkla style) — for Debian 10 and earlier
if [[ -d "$POLKIT_LOCAL_DIR" ]]; then
  run "cat > '${POLKIT_LOCAL_DIR}/49-altiushub-block-installs.pkla' <<'PKLA'
[AltiusHub: require admin for package operations]
Identity=unix-user:*
Action=org.freedesktop.packagekit.*;org.debian.apt.*;io.snapcraft.*;org.flatpak.*
ResultAny=auth_admin
ResultInactive=auth_admin
ResultActive=auth_admin
PKLA"
fi

# Ensure polkit treats 'sudo' group as administrators
if [[ -d "$POLKIT_RULES_DIR" ]]; then
  run "cat > '${POLKIT_RULES_DIR}/49-altiushub-admin-group.rules' <<'RULES'
// AltiusHub: members of the 'sudo' group are polkit admins
polkit.addAdminRule(function(action, subject) {
    return ['unix-group:sudo'];
});
RULES"
fi

run "systemctl restart polkit.service 2>/dev/null || true"

# ---- 1.5 Block CLI package managers for non-sudoers -----------------------
log "----- 1.5 Block CLI installs (apt, dpkg, snap, flatpak) -----"
BLOCK_BINARIES=(
  /usr/bin/apt
  /usr/bin/apt-get
  /usr/bin/aptitude
  /usr/bin/dpkg
  /usr/bin/snap
  /usr/bin/flatpak
  /usr/bin/gdebi
  /usr/bin/gdebi-gtk
  /usr/bin/synaptic
)

ORIG_PERMS_FILE="/var/lib/altiushub-original-perms.txt"
for bin in "${BLOCK_BINARIES[@]}"; do
  if [[ -x "$bin" ]]; then
    # Save original perms once (for rollback)
    if [[ ! -f "$ORIG_PERMS_FILE" ]] || ! grep -q "^${bin} " "$ORIG_PERMS_FILE" 2>/dev/null; then
      run "echo \"$bin $(stat -c '%a %U %G' "$bin")\" >> '$ORIG_PERMS_FILE'"
    fi
    run "chown root:sudo '$bin'"
    run "chmod 750 '$bin'"
    log "Locked: $bin (now root:sudo 750)"
  fi
done

# Also block 'add-apt-repository' and PPA tools
for bin in /usr/bin/add-apt-repository /usr/bin/software-properties-gtk; do
  if [[ -x "$bin" ]]; then
    run "chown root:sudo '$bin'"
    run "chmod 750 '$bin'"
  fi
done

# ---- 1.6 Disable Bluetooth (service + kernel module) ----------------------
log "----- 1.6 Disable Bluetooth -----"

# Service layer: stop, disable, mask so it cannot be re-enabled by users
if systemctl list-unit-files | grep -q '^bluetooth\.service'; then
  run "systemctl stop bluetooth.service 2>/dev/null || true"
  run "systemctl disable bluetooth.service 2>/dev/null || true"
  run "systemctl mask bluetooth.service"
  log "bluetooth.service stopped, disabled, and masked."
else
  log "bluetooth.service not present — skipping service step."
fi

# Kernel layer: blacklist modules so GUI toggles cannot bring it up
run "cat > /etc/modprobe.d/altiushub-bluetooth-blacklist.conf <<'EOF'
# AltiusHub: prevent Bluetooth from loading at boot or runtime
blacklist bluetooth
blacklist btusb
blacklist btintel
blacklist btbcm
blacklist btrtl
blacklist btmtk
install bluetooth /bin/false
install btusb     /bin/false
EOF"

# Unload modules now if loaded
for mod in btusb bluetooth; do
  if lsmod | grep -q "^${mod}"; then
    run "modprobe -r '$mod' 2>/dev/null || true"
  fi
done

# Block via rfkill as a third layer
if command -v rfkill >/dev/null 2>&1; then
  run "rfkill block bluetooth 2>/dev/null || true"
fi

# Rebuild initramfs so the blacklist takes effect on every boot
if command -v update-initramfs >/dev/null 2>&1; then
  run "update-initramfs -u"
fi

STATUS_HARDEN="done"
log "MODULE 1 complete."

###############################################################################
# MODULE 2 — BROWSER EXTENSION CONTROL (Chrome + Edge)
###############################################################################
section "MODULE 2 — BROWSER EXTENSION CONTROL"

# Block every extension with "*", then allow only the approved IDs.
# Uses the current policy keys (ExtensionInstallBlocklist / ExtensionInstallAllowlist).
# Policy is read by the browser at startup; it applies on NEXT launch — no forced
# restart here (you don't kill live user sessions on a fleet push).
write_browser_policy() {
  local dir="$1" label="$2" allowlist="$3"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY-RUN: would write $label policy to $dir/$BROWSER_POLICY_FILE"
    return 0
  fi
  mkdir -p "$dir"
  # Chrome/Edge read managed policy as the logged-in user, not as root.
  # The dir chain must be world-traversable (+x) and the JSON world-readable,
  # otherwise the browser silently fails to load the policy. Explicit chmod
  # protects against any inherited umask from earlier in the script.
  chmod 755 "$dir" "$(dirname "$dir")" "$(dirname "$(dirname "$dir")")"
  cat > "$dir/$BROWSER_POLICY_FILE" <<EOF
{
  "ExtensionInstallBlocklist": ["*"],
  "ExtensionInstallAllowlist": $allowlist
}
EOF
  chmod 644 "$dir/$BROWSER_POLICY_FILE"
  log "$label policy written -> $dir/$BROWSER_POLICY_FILE"
}

write_browser_policy "$CHROME_MANAGED_DIR" "Chrome" "$CHROME_ALLOWLIST"
write_browser_policy "$EDGE_MANAGED_DIR"   "Edge"   "$EDGE_ALLOWLIST"

log "Browser policy applies on next launch of each browser (no live restart forced)."
STATUS_BROWSER="done"
log "MODULE 2 complete."

###############################################################################
# MODULE 3 — VS CODE MARKETPLACE LOCKDOWN
###############################################################################
section "MODULE 3 — VS CODE MARKETPLACE LOCKDOWN"

# Removes 'extensionsGallery' from product.json so the built-in Marketplace is
# disabled. Extensions are pushed from the remote terminal instead.
# Soft-skips if VS Code (or python3) is not present — a missing component must
# NOT abort the whole policy.
if [[ ! -f "$VSCODE_PRODUCT" ]]; then
  log "VS Code not found at $VSCODE_PRODUCT — skipping (will not abort policy)."
  STATUS_VSCODE="skipped (not installed)"
elif ! command -v python3 >/dev/null 2>&1; then
  log "python3 not available — cannot edit product.json. Skipping VS Code lockdown."
  STATUS_VSCODE="skipped (no python3)"
elif [[ $DRY_RUN -eq 1 ]]; then
  log "DRY-RUN: would back up product.json and remove 'extensionsGallery'."
  STATUS_VSCODE="dry-run"
else
  [[ -f "${VSCODE_PRODUCT}.bak" ]] || cp "$VSCODE_PRODUCT" "${VSCODE_PRODUCT}.bak"
  if python3 - "$VSCODE_PRODUCT" <<'PYEOF'
import json, sys
path = sys.argv[1]
with open(path) as f:
    data = json.load(f)
data.pop("extensionsGallery", None)
with open(path, "w") as f:
    json.dump(data, f, indent=4)
print("Marketplace disabled.")
PYEOF
  then
    log "VS Code marketplace disabled (extensionsGallery removed from product.json)."
    log "Fully quit VS Code (all windows + tray) before reopening for it to take effect."
    STATUS_VSCODE="done"
  else
    log "WARN: VS Code product.json edit failed — check file perms / JSON validity."
    STATUS_VSCODE="failed"
  fi
fi
log "MODULE 3 complete."

###############################################################################
# FINAL SUMMARY
###############################################################################
section "DEPLOYMENT SUMMARY"
log "Host:               $(hostname)"
log "Module 1 hardening: $STATUS_HARDEN"
log "Module 2 browsers:  $STATUS_BROWSER"
log "Module 3 VS Code:   $STATUS_VSCODE"
log "Admin user:         $ADMIN_USER"
log "Credentials file:   $CRED_FILE  (root-readable only)"
log "Log file:           $LOG_FILE"

if [[ $DRY_RUN -eq 0 ]]; then
  echo
  echo "=============================================================="
  echo " AltiusHub admin (use to authenticate installs / sudo):"
  echo "   Username: $ADMIN_USER"
  echo "   Password: $EFFECTIVE_PASSWORD"
  echo " Also written to: $CRED_FILE"
  echo "=============================================================="
fi

log "Demoted users will see the change on their NEXT LOGIN."
log "Browser extension policy applies on NEXT browser launch."
log "AltiusHub MDM policy run complete."
exit 0
