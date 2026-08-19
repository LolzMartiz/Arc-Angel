#!/bin/bash
# =============================================================================================
#  clearCacheMac.sh
#  Microsoft 365 tenant-to-tenant post-migration cache, token and session cleanup for macOS.
#
#  macOS port of the Windows Invoke-PostMigrationCleanup.ps1 (v2.0.0).
#
#  WHAT IT DOES
#    Clears cached sign-in tokens, keychain credential material and application caches left
#    behind by a Microsoft 365 tenant-to-tenant migration, so that Outlook, Teams, OneDrive,
#    Office and browsers (Chrome / Edge / Safari) re-authenticate against the NEW tenant
#    instead of silently reusing OLD tenant tokens. Also removes the Microsoft "work account"
#    material on the Mac: OneAuth/MSAL token stores, Workplace-Join keychain entries, the
#    MS-Organization-Access device certificate and Company Portal caches.
#
#  DESIGNED FOR: unattended one-liner execution from an RMM as root, e.g.
#    curl -fsSL https://raw.githubusercontent.com/<org>/<repo>/main/clearCacheMac.sh | bash
#
#  KEY DESIGN POINT - WHY A NAIVE SCRIPT FAILS ON MAC
#    RMM agents run as root. $HOME under root is /var/root, so a naive script "succeeds"
#    while deleting nothing from any real user. This script therefore:
#      1. Detects its own security context.
#      2. Resolves real user accounts from Directory Services (dscl), never from $HOME.
#      3. Runs keychain work inside the console user's session via
#         `launchctl asuser <uid> sudo -u <user>` - the login keychain is per-user,
#         session-bound and unreachable from a bare root context.
#      4. Detects Full Disk Access problems (Safari data is TCC-protected even from root)
#         and reports instead of silently failing.
#
#  SAFETY GUARANTEES (hard-coded, not optional)
#    * NEVER creates, modifies, disables or deletes any user account.
#    * NEVER touches Documents, Desktop, Downloads, Pictures, Movies, Music.
#    * NEVER deletes mail archive files: any .olm or .pst found inside a folder that is
#      about to be removed is rescued to ~/Documents/Outlook Archives (preserved)/ first.
#    * NEVER touches synced OneDrive files (~/Library/CloudStorage, ~/OneDrive*).
#    * NEVER deletes browser Bookmarks, saved passwords (Login Data / keychain
#      "Safe Storage" keys for Chrome & Edge), Web Data (autofill), Extensions, History.
#    * NEVER unenrolls MDM. Enrollment state is detected and reported only.
#    * Every deletion path is validated against a guard function before any I/O occurs.
#    * DRY-RUN mode performs a full pass with zero writes.
#
#  USAGE (flags after `bash -s --` when piping from curl):
#    curl -fsSL <RAW_URL> | bash -s -- --dry-run
#    curl -fsSL <RAW_URL> | bash -s -- --scope aggressive --force
#
#  FLAGS
#    --scope cache|standard|aggressive   Default: standard
#         cache      = file caches only. No keychain, no OneDrive unlink, no Outlook
#                      profile reset, no work-account removal. Safest.
#         standard   = cache + keychain token revocation + OneAuth account-store purge
#                      + Office identity + OneDrive unlink + Outlook profile reset
#                      + work-account (WPJ) removal + browser web-app sign-out
#                      (cookies, Local Storage, IndexedDB - where MSAL keeps tokens).
#         aggressive = standard + all Microsoft HTTPStorages (not just app-matched).
#    --dry-run              Report everything, change nothing.
#    --force                Kill apps immediately (no graceful-quit grace period).
#    --grace N              Seconds to wait for graceful app quit (default 15).
#    --console-user-only    Only process the signed-in user (default: all local users
#                           for file caches; keychain is always console-user only).
#    --skip-browsers        Do not touch Safari / Chrome / Edge.
#    --skip-onedrive        Do not unlink the OneDrive account.
#    --skip-outlook-profile Keep Outlook profile data (old-tenant mail cache stays).
#    --skip-keychain        Do not touch the keychain at all.
#    --skip-workaccount     Do not remove work-account / Workplace-Join material.
#    --log-dir PATH         Default /Library/Logs/PostMigrationCleanup
#
#  EXIT CODES
#    0  success       1  completed with warnings      2  fatal error
#    3  no eligible user found (RMM should retry at next user login)
#
#  NOTE ON REBOOT: this script does NOT reboot the Mac. Apps are fully quit before
#  cleanup so changes take effect immediately; if anything could not be released the
#  summary prints "RESTART RECOMMENDED" and exits with a warning code instead.
# =============================================================================================

set -u

SCRIPT_VERSION="1.3.0"

# ------------------------------- defaults / argument parsing --------------------------------
SCOPE="standard"
DRY_RUN=0
FORCE=0
GRACE=15
CONSOLE_ONLY=0
SKIP_BROWSERS=0
SKIP_ONEDRIVE=0
SKIP_OUTLOOK_PROFILE=0
SKIP_KEYCHAIN=0
SKIP_WORKACCOUNT=0
LOG_DIR="/Library/Logs/PostMigrationCleanup"

while [ $# -gt 0 ]; do
    case "$1" in
        --scope)                SCOPE="${2:-standard}"; shift 2 ;;
        --dry-run)              DRY_RUN=1; shift ;;
        --force)                FORCE=1; shift ;;
        --grace)                GRACE="${2:-15}"; shift 2 ;;
        --console-user-only)    CONSOLE_ONLY=1; shift ;;
        --skip-browsers)        SKIP_BROWSERS=1; shift ;;
        --skip-onedrive)        SKIP_ONEDRIVE=1; shift ;;
        --skip-outlook-profile) SKIP_OUTLOOK_PROFILE=1; shift ;;
        --skip-keychain)        SKIP_KEYCHAIN=1; shift ;;
        --skip-workaccount)     SKIP_WORKACCOUNT=1; shift ;;
        --log-dir)              LOG_DIR="${2:-$LOG_DIR}"; shift 2 ;;
        *) echo "Unknown flag: $1" >&2; shift ;;
    esac
done

case "$SCOPE" in cache|standard|aggressive) : ;; *)
    echo "Invalid --scope '$SCOPE' (cache|standard|aggressive)" >&2; exit 2 ;;
esac

# ------------------------------------- script state -----------------------------------------
WARN_COUNT=0
ERROR_COUNT=0
ITEMS_REMOVED=0
BYTES_FREED=0
RESTART_RECOMMENDED=0
PROCESSED_USERS=0
START_EPOCH=$(date +%s)
HOSTNAME_SHORT=$(hostname -s 2>/dev/null || echo "unknown-mac")
LOG_FILE=""
RECEIPT_FILE=""
CONSOLE_USER=""
CONSOLE_UID=""

# ---------------------------------------- logging -------------------------------------------
init_logging() {
    if ! mkdir -p "$LOG_DIR" 2>/dev/null; then
        LOG_DIR="/tmp/PostMigrationCleanup"
        mkdir -p "$LOG_DIR" 2>/dev/null
    fi
    local stamp; stamp=$(date +%Y%m%d-%H%M%S)
    LOG_FILE="$LOG_DIR/PostMigrationCleanup-$HOSTNAME_SHORT-$stamp.log"
    RECEIPT_FILE="$LOG_DIR/receipt-$HOSTNAME_SHORT-$stamp.json"
    : > "$LOG_FILE" 2>/dev/null || LOG_FILE=""
}

log() {
    # log LEVEL message...
    local level="$1"; shift
    local line
    line="[$(date '+%Y-%m-%d %H:%M:%S')] [$(printf '%-5s' "$level")] $*"
    echo "$line"
    [ -n "$LOG_FILE" ] && echo "$line" >> "$LOG_FILE" 2>/dev/null
    case "$level" in
        WARN)  WARN_COUNT=$((WARN_COUNT + 1)) ;;
        ERROR) ERROR_COUNT=$((ERROR_COUNT + 1)) ;;
    esac
    return 0
}

fmt_bytes() {
    local b="${1:-0}"
    if   [ "$b" -ge 1073741824 ]; then echo "$((b / 1073741824)) GB"
    elif [ "$b" -ge 1048576 ];    then echo "$((b / 1048576)) MB"
    elif [ "$b" -ge 1024 ];       then echo "$((b / 1024)) KB"
    else echo "${b} B"; fi
}

# --------------------------------------- safety guard ---------------------------------------
path_is_safe() {
    # path_is_safe <path> <user_home>
    # Returns 0 only when <path> is strictly inside <user_home>, is not the home itself,
    # is not a protected user-data folder, and is not a OneDrive sync location.
    local p="$1" home="$2"

    [ -n "$p" ] || return 1
    [ -n "$home" ] || return 1
    [ "$home" != "/" ] || return 1

    # Home must be a real per-user home (allow override for lab testing only).
    case "$home" in
        /Users/*) : ;;
        *) [ "${PMC_ALLOW_NONSTANDARD_HOME:-0}" = "1" ] || return 1 ;;
    esac

    # Normalise trailing slashes.
    p="${p%/}"; home="${home%/}"
    [ -n "$p" ] || return 1

    # Must not be the home itself and must live inside it.
    [ "$p" = "$home" ] && return 1
    case "$p" in
        "$home"/*) : ;;
        *) return 1 ;;
    esac

    # No relative-path tricks.
    case "$p" in
        *"/../"*|*"/.."|*"/./"*) return 1 ;;
    esac

    # Never inside protected user-data folders.
    local leaf
    for leaf in Documents Desktop Downloads Pictures Movies Music Public Applications; do
        case "$p" in
            "$home/$leaf"|"$home/$leaf"/*) return 1 ;;
        esac
    done

    # Never inside synced cloud files.
    case "$p" in
        "$home/Library/CloudStorage"|"$home/Library/CloudStorage"/*) return 1 ;;
        "$home/OneDrive"*|"$home/Library/Mobile Documents"*) return 1 ;;
    esac

    return 0
}

folder_size_kb() {
    local p="$1"
    [ -e "$p" ] || { echo 0; return; }
    du -sk "$p" 2>/dev/null | awk '{print $1+0}'
}

remove_path() {
    # remove_path <path> <user_home> <description>
    # Deletes a file or directory entirely (guarded).
    local p="$1" home="$2" desc="$3"

    if [ ! -e "$p" ] && [ ! -L "$p" ]; then
        log SKIP "$desc - not present."
        return 0
    fi
    if ! path_is_safe "$p" "$home"; then
        log ERROR "$desc - BLOCKED by safety guard: $p"
        return 1
    fi

    local kb; kb=$(folder_size_kb "$p")
    if [ "$DRY_RUN" = "1" ]; then
        log DRY "$desc - WOULD remove $p ($(fmt_bytes $((kb * 1024))))"
        return 0
    fi

    chflags -R nouchg "$p" 2>/dev/null
    if rm -rf "$p" 2>/dev/null && [ ! -e "$p" ]; then
        BYTES_FREED=$((BYTES_FREED + kb * 1024))
        ITEMS_REMOVED=$((ITEMS_REMOVED + 1))
        log OK "$desc - removed ($(fmt_bytes $((kb * 1024))))"
    else
        log WARN "$desc - could not fully remove $p (file may be locked; a restart will release it)."
        RESTART_RECOMMENDED=1
    fi
    return 0
}

clear_folder() {
    # clear_folder <path> <user_home> <description>
    # Empties a folder but keeps the folder itself.
    local p="$1" home="$2" desc="$3"

    if [ ! -d "$p" ]; then
        log SKIP "$desc - not present."
        return 0
    fi
    if ! path_is_safe "$p" "$home"; then
        log ERROR "$desc - BLOCKED by safety guard: $p"
        return 1
    fi

    local kb; kb=$(folder_size_kb "$p")
    if [ "$DRY_RUN" = "1" ]; then
        log DRY "$desc - WOULD clear $p ($(fmt_bytes $((kb * 1024))))"
        return 0
    fi

    chflags -R nouchg "$p" 2>/dev/null
    # Delete children only; -mindepth avoids the folder itself.
    find "$p" -mindepth 1 -maxdepth 1 \( -type f -o -type d -o -type l \) -exec rm -rf {} + 2>/dev/null

    local leftover
    leftover=$(find "$p" -mindepth 1 -maxdepth 1 2>/dev/null | head -1)
    if [ -z "$leftover" ]; then
        BYTES_FREED=$((BYTES_FREED + kb * 1024))
        ITEMS_REMOVED=$((ITEMS_REMOVED + 1))
        log OK "$desc - cleared ($(fmt_bytes $((kb * 1024))))"
    else
        BYTES_FREED=$((BYTES_FREED + kb * 1024))
        log WARN "$desc - partially cleared, some items still locked. A restart will release them."
        RESTART_RECOMMENDED=1
    fi
    return 0
}

# -------------------------------- user & session resolution ---------------------------------
get_console_user() {
    # scutil is the reliable way; stat /dev/console reports root at the loginwindow.
    local u
    u=$(echo "show State:/Users/ConsoleUser" | scutil 2>/dev/null | awk '/Name :/ && ! /loginwindow/ { print $3 }')
    if [ -n "$u" ] && [ "$u" != "root" ] && [ "$u" != "loginwindow" ]; then
        CONSOLE_USER="$u"
        CONSOLE_UID=$(id -u "$u" 2>/dev/null || echo "")
    fi
}

list_local_users() {
    # Real accounts: UID >= 500, not _service accounts, home under /Users (or test override).
    dscl . -list /Users UniqueID 2>/dev/null | awk '$2 >= 500 && $1 !~ /^_/ {print $1}'
}

user_home() {
    dscl . -read "/Users/$1" NFSHomeDirectory 2>/dev/null | awk '{print $2; exit}'
}

run_as_user() {
    # run_as_user <username> <uid> <command...>
    # Executes inside the user's GUI/bootstrap session (required for keychain, defaults, osascript).
    local u="$1" uid="$2"; shift 2
    launchctl asuser "$uid" sudo -u "$u" "$@" 2>/dev/null
}

# ----------------------------------- application shutdown -----------------------------------
quit_apps() {
    log STEP "--- Closing applications ---"

    local gui_apps=(
        "Microsoft Word" "Microsoft Excel" "Microsoft PowerPoint"
        "Microsoft Outlook" "Microsoft OneNote"
        "Microsoft Teams" "Microsoft Teams classic" "Microsoft Teams (work or school)"
        "OneDrive" "Company Portal"
    )
    if [ "$SKIP_BROWSERS" != "1" ]; then
        gui_apps+=("Safari" "Google Chrome" "Microsoft Edge")
    fi

    # Process patterns for the hard-kill pass (covers helpers the GUI quit misses).
    local kill_patterns=(
        "Microsoft Word" "Microsoft Excel" "Microsoft PowerPoint" "Microsoft Outlook"
        "Microsoft OneNote" "com.microsoft.teams2" "MSTeams" "Microsoft Teams"
        "OneDrive" "Company Portal" "Microsoft AutoUpdate" "Microsoft Update Assistant"
    )
    if [ "$SKIP_BROWSERS" != "1" ]; then
        kill_patterns+=("Google Chrome" "Microsoft Edge" "Safari")
    fi

    if [ "$DRY_RUN" = "1" ]; then
        log DRY "WOULD quit: ${gui_apps[*]}"
        return 0
    fi

    # Phase 1: polite quit via AppleScript inside the console user's session.
    if [ "$FORCE" != "1" ] && [ -n "$CONSOLE_USER" ] && [ -n "$CONSOLE_UID" ]; then
        local app
        for app in "${gui_apps[@]}"; do
            run_as_user "$CONSOLE_USER" "$CONSOLE_UID" \
                osascript -e "tell application \"$app\" to if it is running then quit" >/dev/null 2>&1
        done
        log INFO "Graceful quit requested. Waiting up to ${GRACE}s..."
        local waited=0
        while [ "$waited" -lt "$GRACE" ]; do
            if ! pgrep -f "com.microsoft.teams2|Microsoft (Word|Excel|PowerPoint|Outlook|OneNote)|OneDrive" >/dev/null 2>&1; then
                break
            fi
            sleep 2; waited=$((waited + 2))
        done
    fi

    # Phase 2: SIGTERM, then SIGKILL.
    local pat
    for pat in "${kill_patterns[@]}"; do
        pkill -TERM -f "$pat" 2>/dev/null
    done
    sleep 3
    for pat in "${kill_patterns[@]}"; do
        pkill -KILL -f "$pat" 2>/dev/null
    done
    sleep 1
    log OK "Target applications closed."
    return 0
}

# ------------------------------- cleanup: Office identity/caches ----------------------------
clean_office() {
    local home="$1" uname="$2"
    log STEP "--- Office identity and token caches: $uname ---"

    local gc="$home/Library/Group Containers"
    local ct="$home/Library/Containers"

    # OneAuth / MSAL token store (the Mac equivalent of IdentityCache + OneAuth on Windows).
    remove_path "$gc/UBF8T346G9.com.microsoft.oneauth" "$home" "OneAuth token store (group container)"
    remove_path "$home/Library/Application Scripts/UBF8T346G9.com.microsoft.oneauth" "$home" "OneAuth application scripts"

    # Office identity, licence tokens and RMS/MIP caches bound to the old tenant.
    remove_path "$gc/UBF8T346G9.Office/Identity"  "$home" "Office identity store"
    remove_path "$gc/UBF8T346G9.Office/Licenses"  "$home" "Office licence token cache"
    remove_path "$gc/UBF8T346G9.Office/mip_policy" "$home" "Office MIP/sensitivity-label cache"
    remove_path "$gc/UBF8T346G9.Office/DRM_Evo.plist" "$home" "Office RMS cache"
    remove_path "$gc/UBF8T346G9.Office/com.microsoft.Office365.plist"   "$home" "Office 365 licensing plist"
    remove_path "$gc/UBF8T346G9.Office/com.microsoft.Office365V2.plist" "$home" "Office 365 licensing plist (V2)"
    remove_path "$gc/UBF8T346G9.Office/MicrosoftRegistrationDB.reg" "$home" "Office registration DB"

    # Licensing helper daemon containers.
    remove_path "$ct/com.microsoft.Office365ServiceV2" "$home" "Office 365 licensing helper container"
    remove_path "$ct/com.microsoft.RMS-XPCService"     "$home" "RMS XPC service container"

    # Per-app container caches (never the whole container - that holds user settings).
    local appid
    for appid in com.microsoft.Word com.microsoft.Excel com.microsoft.Powerpoint com.microsoft.onenote.mac; do
        clear_folder "$ct/$appid/Data/Library/Caches" "$home" "$appid cache"
    done

    # Cookie/HTTP storage for Office apps (holds old-tenant web session cookies).
    local hs="$home/Library/HTTPStorages"
    if [ -d "$hs" ]; then
        local d
        for d in "$hs"/com.microsoft.*; do
            [ -e "$d" ] || continue
            case "$(basename "$d")" in
                com.microsoft.Word*|com.microsoft.Excel*|com.microsoft.Powerpoint*|com.microsoft.Outlook*|com.microsoft.onenote*|com.microsoft.teams*|com.microsoft.OneDrive*|com.microsoft.CompanyPortal*|com.microsoft.Office365ServiceV2*)
                    remove_path "$d" "$home" "HTTP storage $(basename "$d")" ;;
                *)
                    if [ "$SCOPE" = "aggressive" ]; then
                        remove_path "$d" "$home" "HTTP storage $(basename "$d") (aggressive)"
                    fi ;;
            esac
        done
    fi

    # MSA login hint (pre-fills the OLD tenant address at sign-in).
    remove_path "$home/Library/Preferences/com.microsoft.msa-login-hint.plist" "$home" "MSA login hint"
    return 0
}

clean_office_prefs_userctx() {
    # Preference resets that must run through cfprefsd in the user's session.
    local uname="$1" uid="$2"
    [ -n "$uid" ] || return 0
    if [ "$DRY_RUN" = "1" ]; then
        log DRY "WOULD reset Office sign-in preferences for $uname (OfficeActivationEmailAddress, ResetOneAuthCreds)"
        return 0
    fi
    run_as_user "$uname" "$uid" defaults delete com.microsoft.office OfficeActivationEmailAddress >/dev/null 2>&1
    # Microsoft-sanctioned OneAuth reset: the next launch of each app clears any remaining
    # OneAuth account state (accounts shown in the sign-in picker included).
    local dom
    for dom in com.microsoft.Word com.microsoft.Excel com.microsoft.Powerpoint \
               com.microsoft.Outlook com.microsoft.onenote.mac com.microsoft.teams2; do
        run_as_user "$uname" "$uid" defaults write "$dom" ResetOneAuthCreds -bool YES >/dev/null 2>&1
    done
    run_as_user "$uname" "$uid" killall cfprefsd >/dev/null 2>&1
    log OK "Office sign-in preferences reset for $uname (ResetOneAuthCreds staged for all Microsoft apps)."
    return 0
}

# --------------------------- mail archive rescue (.olm / .pst) -------------------------------
preserve_archives() {
    # preserve_archives <dir_about_to_be_deleted> <user_home> <owner_username>
    # Moves every .olm / .pst file (case-insensitive) out of a folder that is about to be
    # removed, into ~/Documents/Outlook Archives (preserved)/<timestamp>/. Documents is
    # protected by the safety guard, so rescued archives can never be deleted by this script.
    local dir="$1" home="$2" owner="$3"

    [ -d "$dir" ] || return 0

    local archives
    archives=$(find "$dir" -type f \( -iname "*.olm" -o -iname "*.pst" \) 2>/dev/null)
    [ -n "$archives" ] || return 0

    local dest
    dest="$home/Documents/Outlook Archives (preserved)/$(date +%Y%m%d-%H%M%S)"

    if [ "$DRY_RUN" = "1" ]; then
        echo "$archives" | while IFS= read -r f; do
            [ -n "$f" ] || continue
            log DRY "WOULD preserve mail archive: $f -> $dest/"
        done
        return 0
    fi

    if ! mkdir -p "$dest" 2>/dev/null; then
        log ERROR "Could not create archive rescue folder '$dest' - $dir will NOT be deleted."
        return 1
    fi

    local failed=0
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        local base target n
        base=$(basename "$f")
        target="$dest/$base"
        n=1
        while [ -e "$target" ]; do
            target="$dest/${base%.*} ($n).${base##*.}"
            n=$((n + 1))
        done
        if mv "$f" "$target" 2>/dev/null; then
            log OK "PRESERVED mail archive: $base -> $target"
        else
            log ERROR "Could not rescue mail archive: $f - its parent folder will NOT be deleted."
            failed=1
        fi
    done <<EOF_ARCH
$archives
EOF_ARCH

    # Hand the rescued files back to the user (script runs as root).
    chown -R "$owner" "$home/Documents/Outlook Archives (preserved)" 2>/dev/null

    return $failed
}

# ------------------------------------ cleanup: Outlook ---------------------------------------
clean_outlook() {
    local home="$1" uname="$2"
    log STEP "--- Outlook: $uname ---"

    local gc="$home/Library/Group Containers"
    local ct="$home/Library/Containers"

    # Container = caches, temp state, webview storage. Safe; rebuilds on next launch.
    # Rescue any .olm/.pst archives first - they are user data, never deleted.
    if preserve_archives "$ct/com.microsoft.Outlook" "$home" "$uname"; then
        remove_path "$ct/com.microsoft.Outlook" "$home" "Outlook app container (caches/session)"
    else
        log WARN "Outlook app container kept in place because a mail archive could not be rescued."
    fi
    remove_path "$ct/com.microsoft.Outlook.CalendarWidget" "$home" "Outlook calendar widget container"

    if [ "$SCOPE" = "cache" ] || [ "$SKIP_OUTLOOK_PROFILE" = "1" ]; then
        log SKIP "Outlook profile data preserved (scope/switch). Old-tenant cached mail remains on disk."
        return 0
    fi

    # Profile data = the Mac equivalent of the Windows Outlook profile + OST. Local mail
    # cache belongs to the OLD tenant mailbox and rebuilds from the new tenant on sign-in.
    # NOTE: any POP/"On My Computer" local-only folders live here too - flag loudly.
    if [ -d "$gc/UBF8T346G9.Office/Outlook" ]; then
        log INFO "Removing Outlook profile data - Outlook will run first-time setup at next launch."
        log INFO "If this user kept local-only 'On My Computer' folders, they were part of the old profile."
        # Rescue any .olm/.pst archives out of the profile tree before it is removed.
        if preserve_archives "$gc/UBF8T346G9.Office/Outlook" "$home" "$uname"; then
            remove_path "$gc/UBF8T346G9.Office/Outlook" "$home" "Outlook profile data (old-tenant mail cache)"
        else
            log WARN "Outlook profile data kept in place because a mail archive could not be rescued."
        fi
    else
        log SKIP "Outlook profile data - not present."
    fi
    remove_path "$gc/UBF8T346G9.Office/OutlookProfile.plist" "$home" "Outlook profile pointer plist"
    return 0
}

# ------------------------------------- cleanup: Teams ----------------------------------------
clean_teams() {
    local home="$1" uname="$2"
    log STEP "--- Microsoft Teams: $uname ---"

    local gc="$home/Library/Group Containers"
    local ct="$home/Library/Containers"

    # New Teams (2.x) - Microsoft's documented cache-clear paths.
    remove_path "$gc/UBF8T346G9.com.microsoft.teams" "$home" "New Teams (2.x) group container"
    local tid
    for tid in com.microsoft.teams2 com.microsoft.teams2.launcher com.microsoft.teams2.notificationcenter com.microsoft.teams2.respawn; do
        remove_path "$ct/$tid" "$home" "Teams container $tid"
    done

    # Classic Teams.
    remove_path "$home/Library/Application Support/Microsoft/Teams" "$home" "Classic Teams cache"
    remove_path "$home/Library/Caches/com.microsoft.teams" "$home" "Classic Teams cache folder"

    # Saved state (restores old-tenant windows otherwise).
    local ss
    for ss in "$home/Library/Saved Application State"/com.microsoft.teams*.savedState; do
        [ -e "$ss" ] || continue
        remove_path "$ss" "$home" "Teams saved state $(basename "$ss")"
    done
    return 0
}

# ------------------------------------ cleanup: OneDrive --------------------------------------
clean_onedrive() {
    local home="$1" uname="$2"
    log STEP "--- OneDrive account unlink: $uname ---"

    if [ "$SCOPE" = "cache" ] || [ "$SKIP_ONEDRIVE" = "1" ]; then
        log SKIP "OneDrive unlink skipped by scope or switch."
        return 0
    fi

    log INFO "Synced FILES on disk are never touched - only the account link/settings."

    # Standalone install: settings live here (Business1 = first work account binding).
    clear_folder "$home/Library/Application Support/OneDrive/settings" "$home" "OneDrive settings (standalone)"

    # App Store (sandboxed) install: settings inside the container.
    clear_folder "$home/Library/Containers/com.microsoft.OneDrive-mac/Data/Library/Application Support/OneDrive/settings" "$home" "OneDrive settings (App Store)"

    # Group containers holding sync-client account state.
    remove_path "$home/Library/Group Containers/UBF8T346G9.OneDriveStandaloneSuite"      "$home" "OneDrive standalone suite state"
    remove_path "$home/Library/Group Containers/UBF8T346G9.OneDriveSyncClientSuite"      "$home" "OneDrive sync client suite state"
    remove_path "$home/Library/Group Containers/UBF8T346G9.OfficeOneDriveSyncIntegration" "$home" "OneDrive/Office sync integration state"

    remove_path "$home/Library/Caches/com.microsoft.OneDrive" "$home" "OneDrive cache"
    remove_path "$home/Library/Caches/OneDrive" "$home" "OneDrive cache (legacy name)"

    log INFO "OneDrive will show first-run setup at next launch."
    return 0
}

# --------------------------------- cleanup: Company Portal -----------------------------------
clean_company_portal() {
    local home="$1" uname="$2"

    if [ "$SCOPE" = "cache" ] || [ "$SKIP_WORKACCOUNT" = "1" ]; then
        return 0
    fi
    log STEP "--- Company Portal / work account files: $uname ---"

    remove_path "$home/Library/Application Support/com.microsoft.CompanyPortalMac" "$home" "Company Portal app data"
    remove_path "$home/Library/Application Support/com.microsoft.CompanyPortalMac.usercontext.info" "$home" "Company Portal user context"
    remove_path "$home/Library/Application Support/com.microsoft.CompanyPortal" "$home" "Company Portal app data (legacy)"
    remove_path "$home/Library/Preferences/com.microsoft.CompanyPortalMac.plist" "$home" "Company Portal preferences"
    remove_path "$home/Library/Preferences/group.com.microsoft.CompanyPortalMac.plist" "$home" "Company Portal group preferences"
    remove_path "$home/Library/Caches/com.microsoft.CompanyPortalMac" "$home" "Company Portal cache"
    remove_path "$home/Library/Caches/CompanyPortalCache" "$home" "Company Portal token cache"
    remove_path "$home/Library/Saved Application State/com.microsoft.CompanyPortalMac.savedState" "$home" "Company Portal saved state"
    local ck
    for ck in "$home/Library/Cookies"/com.microsoft.CompanyPortal*.binarycookies; do
        [ -e "$ck" ] || continue
        remove_path "$ck" "$home" "Company Portal cookies $(basename "$ck")"
    done

    # Separate Microsoft keychain database holding Entra entity certificates.
    remove_path "$home/Library/Keychains/Microsoft_Entity_Certificates-db" "$home" "Microsoft entity certificates keychain"
    return 0
}

# ---------------------------------- cleanup: browsers ----------------------------------------
clean_chromium_profile() {
    # clean_chromium_profile <profile_dir> <cache_root_for_profile> <user_home> <label>
    # Surgical: cookies + caches + sessions only. Bookmarks, Login Data (passwords),
    # Web Data (autofill), Extensions, Preferences, History are deliberately preserved.
    local pdir="$1" cdir="$2" home="$3" label="$4"

    local f
    for f in "Network/Cookies" "Network/Cookies-journal" "Network/Cookies-wal" "Network/Cookies-shm" \
             "Cookies" "Cookies-journal" \
             "Current Session" "Current Tabs" "Last Session" "Last Tabs"; do
        if [ -f "$pdir/$f" ]; then
            remove_path "$pdir/$f" "$home" "$label - $f"
        fi
    done

    # Local Storage and IndexedDB are included by default: Microsoft web apps (Teams web,
    # Outlook web) store MSAL refresh tokens there, NOT in cookies - clearing cookies alone
    # leaves the browser silently signed in.
    local d
    local dirs=("Sessions" "Session Storage" "GPUCache" "Service Worker/CacheStorage" "Service Worker/ScriptCache" "Local Storage/leveldb" "IndexedDB")
    for d in "${dirs[@]}"; do
        if [ -d "$pdir/$d" ]; then
            clear_folder "$pdir/$d" "$home" "$label - $d"
        fi
    done

    # Disk caches live under ~/Library/Caches/<vendor>/<profile>.
    for d in "Cache" "Code Cache" "GPUCache"; do
        if [ -d "$cdir/$d" ]; then
            clear_folder "$cdir/$d" "$home" "$label - cache/$d"
        fi
    done

    log INFO "$label - bookmarks, saved passwords, autofill and extensions preserved."
    return 0
}

clean_chromium_browser() {
    # clean_chromium_browser <user_home> <app_support_rel> <caches_rel> <name>
    local home="$1" as_rel="$2" ca_rel="$3" name="$4"
    local base="$home/Library/Application Support/$as_rel"
    local cbase="$home/Library/Caches/$ca_rel"

    if [ ! -d "$base" ]; then
        log SKIP "$name not installed for this user."
        return 0
    fi

    local pdir pname
    for pdir in "$base/Default" "$base"/Profile\ *; do
        [ -d "$pdir" ] || continue
        pname=$(basename "$pdir")
        clean_chromium_profile "$pdir" "$cbase/$pname" "$home" "$name / $pname"
    done
    return 0
}

clean_safari() {
    local home="$1" uname="$2"

    local container="$home/Library/Containers/com.apple.Safari/Data/Library"

    # TCC check: Safari's container is protected - even root needs Full Disk Access.
    if [ -d "$home/Library/Containers/com.apple.Safari" ]; then
        if ! ls "$container" >/dev/null 2>&1; then
            log WARN "Safari data is TCC-protected and this process lacks Full Disk Access."
            log WARN "Grant FDA to your RMM agent (PPPC profile / System Settings > Privacy > Full Disk Access) and re-run."
            return 0
        fi
    else
        log SKIP "Safari container not present for this user."
        return 0
    fi

    # Cookies (Safari recreates the file empty at next launch).
    remove_path "$container/Cookies/Cookies.binarycookies" "$home" "Safari cookies"
    # Legacy cookie store some builds still read.
    remove_path "$home/Library/Cookies/Cookies.binarycookies" "$home" "Safari cookies (legacy path)"

    # THE critical store on modern macOS: WebKit website data. Safari keeps LocalStorage,
    # IndexedDB and ServiceWorkers under WebKit/WebsiteData (or WebsiteDataStore per
    # profile) - this is where MSAL keeps the Teams/Outlook web sign-in. Clearing the
    # whole WebKit tree covers default and per-profile stores. Bookmarks, History and
    # passwords live elsewhere and are untouched.
    clear_folder "$container/WebKit" "$home" "Safari WebKit website data (LocalStorage/IndexedDB/ServiceWorkers)"
    clear_folder "$home/Library/WebKit/com.apple.Safari" "$home" "Safari WebKit website data (legacy path)"

    # Caches - never Bookmarks.plist, History.db, TopSites or passwords (keychain).
    clear_folder "$container/Caches" "$home" "Safari container caches"
    clear_folder "$home/Library/Caches/com.apple.Safari" "$home" "Safari cache"
    remove_path "$home/Library/HTTPStorages/com.apple.Safari" "$home" "Safari HTTP storage"

    # Legacy site-data paths some builds still read.
    clear_folder "$container/Safari/LocalStorage" "$home" "Safari local storage (legacy)"
    clear_folder "$container/Safari/Databases" "$home" "Safari databases (legacy)"

    # Session-restore state (would reopen old-tenant tabs with live page state).
    remove_path "$container/Safari/LastSession.plist" "$home" "Safari last session"
    remove_path "$container/Safari/RecentlyClosedTabs.plist" "$home" "Safari recently closed tabs"

    log INFO "Safari - bookmarks, history and keychain passwords preserved."
    return 0
}

clean_browsers() {
    local home="$1" uname="$2"

    if [ "$SKIP_BROWSERS" = "1" ]; then
        log SKIP "Browser cleanup skipped (--skip-browsers)."
        return 0
    fi
    log STEP "--- Browsers: $uname ---"

    clean_chromium_browser "$home" "Google/Chrome"   "Google/Chrome"   "Google Chrome"
    clean_chromium_browser "$home" "Microsoft Edge"  "Microsoft Edge"  "Microsoft Edge"
    clean_safari "$home" "$uname"
    return 0
}

# ----------------------- keychain: session token revocation (user ctx) -----------------------
kc_delete_generic_label() {
    # loop-delete every generic password matching a label
    local uname="$1" uid="$2" kc="$3" label="$4"
    local n=0
    if [ "$DRY_RUN" = "1" ]; then
        if run_as_user "$uname" "$uid" security find-generic-password -l "$label" "$kc" >/dev/null 2>&1; then
            log DRY "WOULD delete keychain item(s): label '$label'"
        fi
        return 0
    fi
    while run_as_user "$uname" "$uid" security delete-generic-password -l "$label" "$kc" >/dev/null 2>&1; do
        n=$((n + 1)); [ "$n" -ge 25 ] && break
    done
    if [ "$n" -gt 0 ]; then
        ITEMS_REMOVED=$((ITEMS_REMOVED + n))
        log OK "Keychain: deleted $n item(s) with label '$label'"
    fi
    return 0
}

kc_delete_generic_service() {
    local uname="$1" uid="$2" kc="$3" svc="$4"
    local n=0
    if [ "$DRY_RUN" = "1" ]; then
        if run_as_user "$uname" "$uid" security find-generic-password -s "$svc" "$kc" >/dev/null 2>&1; then
            log DRY "WOULD delete keychain item(s): service '$svc'"
        fi
        return 0
    fi
    while run_as_user "$uname" "$uid" security delete-generic-password -s "$svc" "$kc" >/dev/null 2>&1; do
        n=$((n + 1)); [ "$n" -ge 25 ] && break
    done
    if [ "$n" -gt 0 ]; then
        ITEMS_REMOVED=$((ITEMS_REMOVED + n))
        log OK "Keychain: deleted $n item(s) with service '$svc'"
    fi
    return 0
}

kc_delete_generic_account() {
    local uname="$1" uid="$2" kc="$3" acct="$4"
    local n=0
    if [ "$DRY_RUN" = "1" ]; then
        if run_as_user "$uname" "$uid" security find-generic-password -a "$acct" "$kc" >/dev/null 2>&1; then
            log DRY "WOULD delete keychain item(s): account '$acct'"
        fi
        return 0
    fi
    while run_as_user "$uname" "$uid" security delete-generic-password -a "$acct" "$kc" >/dev/null 2>&1; do
        n=$((n + 1)); [ "$n" -ge 25 ] && break
    done
    if [ "$n" -gt 0 ]; then
        ITEMS_REMOVED=$((ITEMS_REMOVED + n))
        log OK "Keychain: deleted $n item(s) with account '$acct'"
    fi
    return 0
}

kc_delete_internet_service() {
    local uname="$1" uid="$2" kc="$3" svc="$4"
    local n=0
    if [ "$DRY_RUN" = "1" ]; then
        if run_as_user "$uname" "$uid" security find-internet-password -s "$svc" "$kc" >/dev/null 2>&1; then
            log DRY "WOULD delete internet password(s): server '$svc'"
        fi
        return 0
    fi
    while run_as_user "$uname" "$uid" security delete-internet-password -s "$svc" "$kc" >/dev/null 2>&1; do
        n=$((n + 1)); [ "$n" -ge 25 ] && break
    done
    if [ "$n" -gt 0 ]; then
        ITEMS_REMOVED=$((ITEMS_REMOVED + n))
        log OK "Keychain: deleted $n internet password(s) for '$svc'"
    fi
    return 0
}

clean_keychain() {
    # The Mac equivalent of Windows Credential Manager cleanup. The login keychain is
    # per-user, session-bound and DPAPI-like: it must be touched inside the user's own
    # session with the keychain unlocked - i.e. only for the signed-in console user.
    local uname="$1" uid="$2" home="$3"

    if [ "$SKIP_KEYCHAIN" = "1" ] || [ "$SCOPE" = "cache" ]; then
        log SKIP "Keychain cleanup skipped by scope or switch."
        return 0
    fi

    log STEP "--- Session token revocation (login keychain): $uname ---"

    local kc="$home/Library/Keychains/login.keychain-db"
    if [ ! -f "$kc" ]; then
        log WARN "login.keychain-db not found for $uname - keychain steps skipped."
        return 0
    fi

    # Explicit allow-list of Microsoft SESSION TOKEN material. These are tokens written by
    # Office / Teams / OneDrive / the broker - NOT passwords the user typed and saved.
    # Chrome/Edge "Safe Storage" keys are deliberately NOT touched (deleting them would
    # destroy the user's saved browser passwords).

    local label
    for label in \
        "Microsoft Office Identities Cache 2" \
        "Microsoft Office Identities Cache 3" \
        "Microsoft Office Identities Settings 2" \
        "Microsoft Office Identities Settings 3" \
        "Microsoft Office Ticket Cache" \
        "Microsoft Office Ticket Cache 2" \
        "Microsoft Office Credentials" \
        "com.microsoft.adalcache" \
        "MicrosoftOfficeRMSCredential" \
        "MSProtection.framework.service" \
        "com.microsoft.office.rmscache" \
        "com.microsoft.OutlookCore.Secret" \
        "com.helpshift.data_com.microsoft.Outlook" \
        "Exchange" \
        "MSOpenTech.ADAL.1" \
        "Microsoft Teams Identities Cache" \
        "teamsIv" \
        "teamsKey" \
        "Teams Safe Storage" \
        "Microsoft Teams (work or school) Safe Storage" \
        "OneDrive Cached Credential" \
        "OneDrive Standalone Cached Credential" \
        "OneDrive Standalone Cached Credential Business - Business1" \
        "OneDrive Standalone Cached Credential Business - Business2" \
        "OneDrive Cached Credential Business - Business1" \
        ; do
        kc_delete_generic_label "$uname" "$uid" "$kc" "$label"
    done

    local svc
    for svc in "OneAuthAccount" "com.microsoft.onedrive.cookies"; do
        kc_delete_generic_service "$uname" "$uid" "$kc" "$svc"
    done

    for svc in "msoCredentialSchemeADAL" "msoCredentialSchemeLiveId"; do
        kc_delete_internet_service "$uname" "$uid" "$kc" "$svc"
    done

    # Purge the OneAuth/MSAL universal storage access group from the data-protection
    # keychain. This is where the broker keeps the ACCOUNT LIST that Office and Teams
    # show in their account pickers - without this, the account entry survives even
    # after its tokens are revoked (user sees their account listed and only gets a
    # password prompt). Same technique Microsoft's office-reset tooling uses.
    local kc2
    kc2=$(find "$home/Library/Keychains" -maxdepth 2 -name "keychain-2.db" 2>/dev/null | head -1)
    if [ -n "$kc2" ] && [ -f "$kc2" ]; then
        if [ "$DRY_RUN" = "1" ]; then
            log DRY "WOULD purge OneAuth universalstorage account/token group from $kc2"
        else
            if sqlite3 "$kc2" "DELETE FROM genp WHERE agrp='UBF8T346G9.com.microsoft.identity.universalstorage';" 2>/dev/null; then
                log OK "Purged OneAuth account/token store (data-protection keychain) - account pickers will be empty."
            else
                log WARN "Could not purge OneAuth universalstorage group (locked) - ResetOneAuthCreds will clear it at next app launch."
            fi
        fi
    else
        log SKIP "Data-protection keychain (keychain-2.db) not found."
    fi

    log OK "Keychain session-token pass complete. Non-Microsoft entries untouched."
    return 0
}

# --------------------------- work account / Entra registration -------------------------------
clean_work_account() {
    # Removes the per-user Entra "work account" registration material (the Mac analog of
    # Windows "Access work or school"): Workplace-Join keychain entries and the
    # MS-Organization-Access device certificate. Device is confirmed NON-MDM by policy;
    # MDM enrollment is detected and reported, never removed.
    local uname="$1" uid="$2" home="$3"

    if [ "$SKIP_WORKACCOUNT" = "1" ] || [ "$SCOPE" = "cache" ] || [ "$SKIP_KEYCHAIN" = "1" ]; then
        log SKIP "Work account removal skipped by scope or switch."
        return 0
    fi

    log STEP "--- Work account / Entra registration removal: $uname ---"

    local kc="$home/Library/Keychains/login.keychain-db"

    # Workplace Join generic-password records.
    local acct
    for acct in \
        "com.microsoft.workplacejoin.thumbprint" \
        "com.microsoft.workplacejoin.registeredUserPrincipalName" \
        "com.microsoft.workplacejoin.deviceOSVersion" \
        "com.microsoft.workplacejoin.devicePatchAttemptTimestamp" \
        "com.microsoft.workplacejoin.tenantId" \
        "com.microsoft.workplacejoin.tenantDisplayName" \
        "com.microsoft.workplacejoin.cloudEnvironment" \
        "com.microsoft.workplacejoin.deviceName" \
        ; do
        kc_delete_generic_account "$uname" "$uid" "$kc" "$acct"
    done

    local label
    for label in \
        "com.microsoft.CompanyPortal" \
        "com.microsoft.CompanyPortalMac" \
        "com.microsoft.CompanyPortal.HockeySDK" \
        "enterpriseregistration.windows.net" \
        "https://enterpriseregistration.windows.net" \
        "https://device.login.microsoftonline.com" \
        ; do
        kc_delete_generic_label "$uname" "$uid" "$kc" "$label"
    done

    # The Entra device certificate + private key (issuer MS-ORGANIZATION-ACCESS,
    # CN = Entra device ID). delete-identity removes cert and key together.
    if [ "$DRY_RUN" = "1" ]; then
        if run_as_user "$uname" "$uid" security find-certificate -c "MS-ORGANIZATION-ACCESS" "$kc" >/dev/null 2>&1 \
        || run_as_user "$uname" "$uid" bash -c "security find-certificate -a '$kc' 2>/dev/null | grep -q MS-ORGANIZATION-ACCESS"; then
            log DRY "WOULD remove MS-ORGANIZATION-ACCESS device certificate/identity"
        fi
    else
        local device_id
        device_id=$(run_as_user "$uname" "$uid" bash -c \
            "security find-certificate -a -Z '$kc' 2>/dev/null | grep -B 9 'MS-ORGANIZATION-ACCESS' | awk -F'\"' '/\"alis\"<blob>=/ {print \$4}' | head -1")
        if [ -n "$device_id" ]; then
            if run_as_user "$uname" "$uid" security delete-identity -c "$device_id" "$kc" >/dev/null 2>&1; then
                log OK "Removed Entra device identity (cert + key) for device ID $device_id."
                ITEMS_REMOVED=$((ITEMS_REMOVED + 1))
            elif run_as_user "$uname" "$uid" security delete-certificate -c "$device_id" "$kc" >/dev/null 2>&1; then
                log OK "Removed Entra device certificate $device_id (key may remain)."
                ITEMS_REMOVED=$((ITEMS_REMOVED + 1))
            else
                log WARN "Found Entra device identity '$device_id' but could not remove it."
            fi
        else
            log SKIP "No MS-ORGANIZATION-ACCESS device certificate found."
        fi
    fi

    log INFO "Reminder: delete the stale device object in the OLD tenant (Entra admin center > Devices)."
    return 0
}

# ----------------------------------- MDM detection (report only) -----------------------------
report_mdm_state() {
    log STEP "--- MDM enrollment state (report only) ---"
    if ! command -v profiles >/dev/null 2>&1; then
        log INFO "profiles tool unavailable - MDM state unknown."
        return 0
    fi
    local status
    status=$(profiles status -type enrollment 2>/dev/null)
    if [ -n "$status" ]; then
        echo "$status" | while IFS= read -r line; do log INFO "  $line"; done
        if echo "$status" | grep -qi "MDM enrollment: Yes"; then
            log WARN "Device reports MDM enrollment. This script will NOT unenroll it - retire it from the MDM console."
        fi
    else
        log INFO "No enrollment status reported (not MDM-enrolled)."
    fi
    return 0
}

# ------------------------------------------ summary ------------------------------------------
write_summary() {
    local dur=$(( $(date +%s) - START_EPOCH ))
    log STEP "================================================================="
    log STEP "                        SUMMARY"
    log STEP "================================================================="
    log INFO "Computer            : $HOSTNAME_SHORT"
    log INFO "Scope               : $SCOPE"
    log INFO "Mode                : $([ "$DRY_RUN" = "1" ] && echo 'DRY RUN - nothing changed' || echo 'LIVE')"
    log INFO "Profiles processed  : $PROCESSED_USERS"
    log INFO "Items removed       : $ITEMS_REMOVED"
    log INFO "Space reclaimed     : $(fmt_bytes "$BYTES_FREED")"
    log INFO "Warnings            : $WARN_COUNT"
    log INFO "Errors              : $ERROR_COUNT"
    log INFO "Restart recommended : $([ "$RESTART_RECOMMENDED" = "1" ] && echo 'YES - some items were locked' || echo 'No')"
    log INFO "Duration            : ${dur}s"
    log INFO "Log file            : ${LOG_FILE:-'(console only)'}"
    log STEP "================================================================="

    # Machine-readable receipt for the RMM to collect.
    if [ -n "$RECEIPT_FILE" ]; then
        {
            printf '{\n'
            printf '  "version": "%s",\n'            "$SCRIPT_VERSION"
            printf '  "computer": "%s",\n'           "$HOSTNAME_SHORT"
            printf '  "scope": "%s",\n'              "$SCOPE"
            printf '  "dryRun": %s,\n'               "$([ "$DRY_RUN" = "1" ] && echo true || echo false)"
            printf '  "profilesHandled": %s,\n'      "$PROCESSED_USERS"
            printf '  "itemsRemoved": %s,\n'         "$ITEMS_REMOVED"
            printf '  "bytesFreed": %s,\n'           "$BYTES_FREED"
            printf '  "warnings": %s,\n'             "$WARN_COUNT"
            printf '  "errors": %s,\n'               "$ERROR_COUNT"
            printf '  "restartRecommended": %s,\n'   "$([ "$RESTART_RECOMMENDED" = "1" ] && echo true || echo false)"
            printf '  "completedUtc": "%s"\n'        "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            printf '}\n'
        } > "$RECEIPT_FILE" 2>/dev/null && log INFO "Receipt written: $RECEIPT_FILE"
    fi
    return 0
}

# ============================================== MAIN ==========================================
init_logging

log STEP "================================================================="
log STEP " Post-Migration Cleanup for macOS  v$SCRIPT_VERSION"
log STEP " Microsoft 365 tenant-to-tenant - cache, token and session reset"
log STEP "================================================================="

if [ "$(id -u)" != "0" ]; then
    log ERROR "This script must run as root (RMM/agent context). Re-run with sudo."
    exit 2
fi

OS_VER=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
log INFO "macOS version    : $OS_VER"
log INFO "Scope            : $SCOPE"
[ "$DRY_RUN" = "1" ] && log DRY "DRY RUN - no changes will be made."

# Keep the Mac awake for the duration of this run.
if command -v caffeinate >/dev/null 2>&1 && [ "$DRY_RUN" != "1" ]; then
    caffeinate -dimsu -w $$ &
fi

get_console_user
if [ -n "$CONSOLE_USER" ]; then
    log INFO "Console user     : $CONSOLE_USER (uid $CONSOLE_UID)"
else
    log WARN "No user is signed in at the GUI. File caches will be cleared for all users,"
    log WARN "but keychain/work-account steps need an unlocked login keychain - they will be"
    log WARN "skipped. Re-run this command after the user signs in to finish token revocation."
fi

# Build target user list.
TARGET_USERS=""
if [ "$CONSOLE_ONLY" = "1" ]; then
    TARGET_USERS="$CONSOLE_USER"
else
    TARGET_USERS=$(list_local_users)
fi
TARGET_USERS=$(echo "$TARGET_USERS" | awk 'NF' | sort -u)

if [ -z "$TARGET_USERS" ]; then
    log ERROR "No eligible user account found on this device. Nothing to do."
    write_summary
    exit 3
fi

log INFO "Target users     : $(echo "$TARGET_USERS" | tr '\n' ' ')"

report_mdm_state
quit_apps

while IFS= read -r U; do
    [ -n "$U" ] || continue
    HOMEDIR=$(user_home "$U")
    if [ -z "$HOMEDIR" ] || [ ! -d "$HOMEDIR" ]; then
        log WARN "User $U has no resolvable home directory - skipped."
        continue
    fi
    case "$HOMEDIR" in
        /Users/*) : ;;
        *) if [ "${PMC_ALLOW_NONSTANDARD_HOME:-0}" != "1" ]; then
               log WARN "User $U home '$HOMEDIR' is outside /Users - skipped for safety."
               continue
           fi ;;
    esac

    UID_N=$(id -u "$U" 2>/dev/null || echo "")

    log STEP "#################################################################"
    log STEP " PROFILE: $U"
    log STEP " Home   : $HOMEDIR"
    log STEP " Active : $([ "$U" = "$CONSOLE_USER" ] && echo yes || echo no)"
    log STEP "#################################################################"

    clean_office        "$HOMEDIR" "$U"
    clean_outlook       "$HOMEDIR" "$U"
    clean_teams         "$HOMEDIR" "$U"
    clean_onedrive      "$HOMEDIR" "$U"
    clean_browsers      "$HOMEDIR" "$U"
    clean_company_portal "$HOMEDIR" "$U"

    # Session-bound steps: only possible for the signed-in console user.
    if [ -n "$CONSOLE_USER" ] && [ "$U" = "$CONSOLE_USER" ] && [ -n "$UID_N" ]; then
        clean_office_prefs_userctx "$U" "$UID_N"
        clean_keychain     "$U" "$UID_N" "$HOMEDIR"
        clean_work_account "$U" "$UID_N" "$HOMEDIR"
    else
        if [ "$SCOPE" != "cache" ] && [ "$SKIP_KEYCHAIN" != "1" ]; then
            log INFO "$U is not the signed-in console user - keychain/work-account steps deferred."
            log INFO "Run this command again while $U is signed in to revoke their keychain tokens."
        fi
    fi

    PROCESSED_USERS=$((PROCESSED_USERS + 1))
done <<EOF_USERS
$TARGET_USERS
EOF_USERS

if [ "$RESTART_RECOMMENDED" = "1" ]; then
    log WARN "*** RESTART RECOMMENDED: some items were locked by running processes. ***"
    log WARN "*** The cleanup is effective now for all cleared items; a restart releases the rest. ***"
fi

write_summary

EXIT_CODE=0
if   [ "$ERROR_COUNT" -gt 0 ]; then EXIT_CODE=2
elif [ "$WARN_COUNT"  -gt 0 ]; then EXIT_CODE=1
fi
log INFO "Exiting with code $EXIT_CODE."
exit $EXIT_CODE
