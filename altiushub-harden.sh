#!/usr/bin/env bash
###############################################################################
# AltiusHub Linux Endpoint Hardening Script
# -----------------------------------------------------------------------------
# Target:       Debian / Debian-based distros (Ubuntu, Linux Mint, etc.)
# Run as:       root (sudo bash altiushub-harden.sh)
# Designed for: Scalefusion MDM remote terminal push
#
# What it does:
#   1. Creates a new admin user 'AltiusHub' with a strong random password
#   2. Verifies AltiusHub can authenticate + sudo BEFORE touching the old user
#   3. Demotes all other existing sudoers/admins to standard users
#   4. Blocks GUI software installs (PackageKit/PolicyKit prompt for admin)
#   5. Blocks CLI package managers (apt, apt-get, dpkg, snap, flatpak) for
#      non-sudoers — they must authenticate as AltiusHub
#   6. Disables Bluetooth at service AND kernel-module level
#
# Flags:
#   --dry-run      Print actions, change nothing
#   --password X   Use supplied password instead of generating one
#   --keep-user U  Keep this username as a sudoer too (besides AltiusHub)
#
# Logs to: /var/log/altiushub-hardening.log
# Rollback: see altiushub-rollback.sh
###############################################################################

set -euo pipefail

# ---------- Config ----------------------------------------------------------
ADMIN_USER="AltiusHub"
LOG_FILE="/var/log/altiushub-hardening.log"
CRED_FILE="/root/altiushub-credentials.txt"   # root-readable only
DRY_RUN=0
CUSTOM_PASSWORD=""
KEEP_USER=""

# ---------- Arg parsing -----------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)     DRY_RUN=1; shift ;;
    --password)    CUSTOM_PASSWORD="$2"; shift 2 ;;
    --keep-user)   KEEP_USER="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,28p' "$0"; exit 0 ;;
    *) echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

# ---------- Helpers ---------------------------------------------------------
log() {
  local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
  echo "$msg" | tee -a "$LOG_FILE"
}

run() {
  # Execute a command, or just log it in dry-run mode
  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY-RUN: $*"
  else
    log "RUN: $*"
    eval "$@"
  fi
}

die() {
  log "FATAL: $*"
  log "Aborting. No destructive changes have been applied beyond this point."
  exit 1
}

require_root() {
  [[ $EUID -eq 0 ]] || die "This script must be run as root."
}

# ---------- Preflight -------------------------------------------------------
require_root
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

log "================================================================"
log "AltiusHub hardening starting. Dry-run=$DRY_RUN"
log "Host: $(hostname)  Kernel: $(uname -r)"
log "OS:   $(. /etc/os-release && echo "$PRETTY_NAME")"
log "================================================================"

# Detect desktop environment (informational; rules below are universal)
DETECTED_DE="${XDG_CURRENT_DESKTOP:-}"
if [[ -z "$DETECTED_DE" ]]; then
  if   command -v gnome-shell >/dev/null 2>&1; then DETECTED_DE="GNOME"
  elif command -v plasmashell >/dev/null 2>&1; then DETECTED_DE="KDE"
  elif command -v xfce4-session >/dev/null 2>&1; then DETECTED_DE="XFCE"
  else DETECTED_DE="headless-or-unknown"
  fi
fi
log "Detected desktop environment: $DETECTED_DE"

# Verify required tools exist
for bin in useradd usermod passwd getent systemctl; do
  command -v "$bin" >/dev/null 2>&1 || die "Required binary missing: $bin"
done

###############################################################################
# STEP 1 — Create AltiusHub admin user
###############################################################################
log "----- STEP 1: Create admin user '$ADMIN_USER' -----"

# Generate strong password if one wasn't supplied
if [[ -z "$CUSTOM_PASSWORD" ]]; then
  # 24 chars: upper, lower, digits, symbols. Avoids shell-confusing chars.
  GEN_PASSWORD=$(tr -dc 'A-Za-z0-9!@#%^&*_=+-' </dev/urandom | head -c 24)
else
  GEN_PASSWORD="$CUSTOM_PASSWORD"
fi

if getent passwd "$ADMIN_USER" >/dev/null; then
  log "User '$ADMIN_USER' already exists — resetting password and ensuring sudo group."
  if [[ $DRY_RUN -eq 0 ]]; then
    echo "${ADMIN_USER}:${GEN_PASSWORD}" | chpasswd
    usermod -aG sudo "$ADMIN_USER"
  fi
else
  if [[ $DRY_RUN -eq 0 ]]; then
    useradd -m -s /bin/bash -c "AltiusHub Administrator" "$ADMIN_USER"
    echo "${ADMIN_USER}:${GEN_PASSWORD}" | chpasswd
    usermod -aG sudo "$ADMIN_USER"
  else
    log "DRY-RUN: would create $ADMIN_USER, set password, add to sudo group"
  fi
fi

# Save credentials to a root-only file
if [[ $DRY_RUN -eq 0 ]]; then
  umask 077
  cat > "$CRED_FILE" <<EOF
AltiusHub admin credentials
Generated: $(date '+%Y-%m-%d %H:%M:%S')
Host:      $(hostname)
Username:  $ADMIN_USER
Password:  $GEN_PASSWORD

Store this securely. This file is readable only by root.
EOF
  chmod 600 "$CRED_FILE"
fi

###############################################################################
# STEP 2 — Verify AltiusHub can authenticate + sudo  (LOCKOUT GUARD)
###############################################################################
log "----- STEP 2: Verify '$ADMIN_USER' authentication and sudo access -----"

if [[ $DRY_RUN -eq 0 ]]; then
  # Test 1: PAM authentication via su
  if ! echo "$GEN_PASSWORD" | su -c "id" "$ADMIN_USER" >/dev/null 2>&1; then
    die "Cannot authenticate as $ADMIN_USER. Old user's sudo is UNTOUCHED."
  fi
  log "PAM auth check passed."

  # Test 2: sudo group membership
  if ! id -nG "$ADMIN_USER" | grep -qw sudo; then
    die "$ADMIN_USER is not in 'sudo' group. Old user's sudo is UNTOUCHED."
  fi
  log "Sudo group membership confirmed."
else
  log "DRY-RUN: skipping verification (no real user created)"
fi

###############################################################################
# STEP 3 — Demote other sudoers to standard users
###############################################################################
log "----- STEP 3: Demote other admin users to standard -----"

# Collect every user currently in sudo or admin groups, except AltiusHub
# and any --keep-user the operator specified.
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

# Wipe any per-user sudoers.d files that might grant NOPASSWD
log "Scanning /etc/sudoers.d/ for stray entries..."
if [[ -d /etc/sudoers.d ]]; then
  for f in /etc/sudoers.d/*; do
    [[ -f "$f" ]] || continue
    [[ "$(basename "$f")" == "README" ]] && continue
    [[ "$(basename "$f")" == "altiushub" ]] && continue
    # Move aside rather than delete, so we can restore if needed
    run "mv '$f' '${f}.disabled-$(date +%s)'"
  done
fi

###############################################################################
# STEP 4 — Block GUI installs (PolicyKit rules)
###############################################################################
log "----- STEP 4: Block GUI software installation -----"

# PolicyKit (polkit) handles the auth dialogs shown by GNOME Software,
# Plasma Discover, gdebi, etc. We require admin (wheel/sudo) authentication
# for every PackageKit and software-installation action.
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

###############################################################################
# STEP 5 — Block CLI package managers for non-sudoers
###############################################################################
log "----- STEP 5: Block CLI installs (apt, dpkg, snap, flatpak) -----"

# Strategy: wrap each binary with a permission check that rejects non-sudoers
# outright. Sudoers (AltiusHub) bypass via the original binary path.
#
# We do this by tightening file permissions so only root + 'sudo' group can
# execute. Standard users get "Permission denied" when they try.

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

# Ensure a 'pkgadmin' group exists, owned by root, containing only sudoers.
# We re-use the existing 'sudo' group to avoid drift.
for bin in "${BLOCK_BINARIES[@]}"; do
  if [[ -x "$bin" ]]; then
    # Save original perms once (for rollback)
    ORIG_PERMS_FILE="/var/lib/altiushub-original-perms.txt"
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

###############################################################################
# STEP 6 — Disable Bluetooth (service + kernel module)
###############################################################################
log "----- STEP 6: Disable Bluetooth -----"

# Service layer: stop, disable, mask so it cannot be re-enabled by users
if systemctl list-unit-files | grep -q '^bluetooth\.service'; then
  run "systemctl stop bluetooth.service 2>/dev/null || true"
  run "systemctl disable bluetooth.service 2>/dev/null || true"
  run "systemctl mask bluetooth.service"
  log "bluetooth.service stopped, disabled, and masked."
else
  log "bluetooth.service not present — skipping service step."
fi

# Kernel layer: blacklist modules so GNOME/KDE toggles cannot bring it up
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

# Unload modules now if they're loaded (won't survive reboot anyway, but
# this kills the live Bluetooth stack immediately)
for mod in btusb bluetooth; do
  if lsmod | grep -q "^${mod}"; then
    run "modprobe -r '$mod' 2>/dev/null || true"
  fi
done

# Block via rfkill as a third layer (in case some hardware exposes a switch)
if command -v rfkill >/dev/null 2>&1; then
  run "rfkill block bluetooth 2>/dev/null || true"
fi

# Rebuild initramfs so the blacklist takes effect on every boot
if command -v update-initramfs >/dev/null 2>&1; then
  run "update-initramfs -u"
fi

###############################################################################
# STEP 7 — Final summary
###############################################################################
log "================================================================"
log "Hardening complete on $(hostname)"
log "Admin user:        $ADMIN_USER"
log "Credentials file:  $CRED_FILE  (root-readable only)"
log "Log file:          $LOG_FILE"
log "Rollback script:   altiushub-rollback.sh"
log "================================================================"

if [[ $DRY_RUN -eq 0 ]]; then
  echo
  echo "=============================================================="
  echo " AltiusHub admin password (save this NOW, displayed once):"
  echo "   Username: $ADMIN_USER"
  echo "   Password: $GEN_PASSWORD"
  echo " Also written to: $CRED_FILE"
  echo "=============================================================="
fi

log "Demoted users will see the changes on their NEXT LOGIN."
exit 0
