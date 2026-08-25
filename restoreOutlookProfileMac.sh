#!/bin/bash
# =============================================================================================
#  restoreOutlookProfileMac.sh
#  Restores the Outlook profile that clearCacheMac.sh v2.x MOVED to
#  "~/Outlook Profile Backup (old tenant) <timestamp>/".
#
#  Nothing is ever deleted. If a NEW profile already exists (because Outlook was opened and
#  set up for the new tenant after the cleanup), it is renamed aside, not overwritten.
#
#  Usage:
#    sudo bash restoreOutlookProfileMac.sh                 # restore for the signed-in user
#    sudo bash restoreOutlookProfileMac.sh <username>
#    sudo bash restoreOutlookProfileMac.sh <username> --list   # just show what backups exist
# =============================================================================================
set -u
PATH="${PMC_PATH_PREFIX:+$PMC_PATH_PREFIX:}/usr/bin:/bin:/usr/sbin:/sbin"; export PATH  # PMC_PATH_PREFIX = test hook only

TARGET_USER="${1:-}"
MODE="${2:-restore}"
case "$TARGET_USER" in --list) TARGET_USER=""; MODE="--list" ;; esac

log() { echo "[$(date '+%H:%M:%S')] $*"; }

[ "$(id -u)" = "0" ] || { echo "Run with sudo: sudo bash restoreOutlookProfileMac.sh"; exit 64; }

if [ -z "$TARGET_USER" ]; then
    TARGET_USER=$(echo "show State:/Users/ConsoleUser" | scutil 2>/dev/null | awk '/Name :/ && ! /loginwindow/ {print $3; exit}')
fi
[ -n "$TARGET_USER" ] && [ "$TARGET_USER" != "root" ] || { echo "Could not determine the user. Pass it: sudo bash restoreOutlookProfileMac.sh <username>"; exit 64; }

HOME_DIR=$(dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2; exit}')
[ -n "$HOME_DIR" ] && [ -d "$HOME_DIR" ] || { echo "No home directory for '$TARGET_USER'."; exit 64; }

GC="$HOME_DIR/Library/Group Containers/UBF8T346G9.Office"
log "User        : $TARGET_USER"
log "Destination : $GC"

# ---- find backups (newest last) ----
found=0
for b in "$HOME_DIR/Outlook Profile Backup (old tenant)"*; do
    [ -d "$b" ] || continue
    found=1
    sz=$(du -sh "$b" 2>/dev/null | awk '{print $1}')
    omc=$(find "$b" -maxdepth 5 -type d -name "Omc" 2>/dev/null | head -1)
    eml=0; [ -n "$omc" ] && eml=$(find "$omc" -type f -name "*.eml" 2>/dev/null | wc -l | tr -d ' ')
    log "FOUND backup: $b  ($sz${eml:+, $eml local .eml messages in Omc})"
    BK="$b"
done
[ "$found" = "1" ] || { log "No backup folder found in $HOME_DIR"; exit 69; }

if [ "$MODE" = "--list" ]; then
    log "Listing only. Re-run without --list to restore the newest backup shown above."
    exit 0
fi

# ---- Outlook must be closed, or the store will be rewritten under us ----
if pgrep -x "Microsoft Outlook" >/dev/null 2>&1; then
    log "Microsoft Outlook is RUNNING. Quit it completely, then re-run. Nothing was changed."
    exit 75
fi

log "Restoring from: $BK"
mkdir -p "$GC" 2>/dev/null

STAMP=$(date +%Y%m%d-%H%M%S)

# ---- if a new profile exists, set it aside instead of overwriting it ----
if [ -d "$GC/Outlook" ]; then
    if mv "$GC/Outlook" "$GC/Outlook-new-tenant-$STAMP"; then
        log "Existing (new-tenant) profile set aside as: Outlook-new-tenant-$STAMP"
        log "  Nothing lost - it is still on disk if you want to switch back."
    else
        log "ERROR: could not move the existing profile aside. Nothing changed."
        exit 1
    fi
fi
if [ -f "$GC/OutlookProfile.plist" ]; then
    mv "$GC/OutlookProfile.plist" "$GC/OutlookProfile-new-tenant-$STAMP.plist" 2>/dev/null
fi

# ---- restore ----
if mv "$BK/Outlook" "$GC/Outlook"; then
    log "RESTORED profile -> $GC/Outlook"
else
    log "ERROR: restore failed. Check permissions/disk. Nothing else changed."
    exit 1
fi
[ -f "$BK/OutlookProfile.plist" ] && mv "$BK/OutlookProfile.plist" "$GC/OutlookProfile.plist" 2>/dev/null && log "RESTORED OutlookProfile.plist"

# ---- ownership must belong to the user (cleanup ran as root) ----
chown -R "$TARGET_USER" "$GC/Outlook" 2>/dev/null
[ -f "$GC/OutlookProfile.plist" ] && chown "$TARGET_USER" "$GC/OutlookProfile.plist" 2>/dev/null
log "Ownership set to $TARGET_USER."

# ---- stale lock from the forced quit can block the Hx store on first open ----
lock=$(find "$GC/Outlook" -maxdepth 4 -name "HxStore.lock" 2>/dev/null | head -1)
[ -n "$lock" ] && log "NOTE: a stale HxStore.lock is present. If Outlook will not open the store, quit Outlook and open it once more."

rmdir "$BK" 2>/dev/null && log "Empty backup folder removed."

echo ""
log "DONE. Next steps in Outlook:"
log "  1. Open Outlook - the OLD profile is back, with 'On My Computer' mail present."
log "  2. Tools > Accounts > select the OLD tenant account > Manage > 'Remove Account'."
log "     *** Use 'Remove Account'. NEVER 'Reset Account' - that deletes local mail. ***"
log "  3. Add the NEW tenant account. 'On My Computer' folders stay intact throughout."
