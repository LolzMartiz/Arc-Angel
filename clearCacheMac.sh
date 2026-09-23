#!/bin/bash
{ # ===== truncation guard: forces bash to parse the whole file before running anything =====

# =============================================================================================
#  clearTeamsMac.sh   v1.0.0
#  Microsoft Teams ONLY - cache and sign-in reset for macOS.
#
#  WHAT IT TOUCHES
#    New Teams (2.x) and classic Teams: containers, group container, caches, cookies,
#    saved window state, preferences, and the Teams keychain items.
#
#  WHAT IT DOES NOT TOUCH (deliberately)
#    Outlook, Word, Excel, PowerPoint, OneNote, OneDrive, Company Portal, browsers,
#    any mail data, any user documents, MDM enrollment - none of it.
#
#    It also leaves the SHARED Microsoft sign-in broker (OneAuth) alone by default.
#    Teams shares that store with the Office apps, so purging it would sign the user out
#    of Word/Excel/Outlook as well. Because of that, after this script Teams shows a
#    sign-in screen, but the account name may still appear in the account picker - the
#    broker still remembers it. Clicking it re-authenticates against the CURRENT tenant.
#    If you need the picker completely empty, pass --also-shared-identity and accept
#    that the Office apps will ask for sign-in too.
#
#  USAGE (run as root - RMM, or sudo)
#    curl -fsSL <RAW_URL> | sudo bash -s -- --dry-run     # rehearsal, changes nothing
#    curl -fsSL <RAW_URL> | sudo bash -s --               # normal run
#
#  FLAGS
#    --dry-run                Report everything, change nothing.
#    --force                  Terminate Teams immediately instead of asking it to quit.
#    --console-user-only      Only the signed-in user (default: every local user).
#    --also-shared-identity   ALSO clear the shared OneAuth broker. Empties the account
#                             picker, but signs out Word/Excel/Outlook/OneDrive as well.
#    --keep-backgrounds       Do not bother preserving custom meeting backgrounds.
#
#  EXIT CODES
#    0 ok   1 completed with warnings   64 not root   75 deferred (Teams still running)
#
#  Custom meeting backgrounds the user uploaded are copied to
#  ~/Teams Backgrounds (preserved)/ before anything is removed.
# =============================================================================================

PATH="${PMC_PATH_PREFIX:+$PMC_PATH_PREFIX:}/usr/bin:/bin:/usr/sbin:/sbin"; export PATH
set -u

VERSION="1.0.0"
DRY=0; FORCE=0; CONSOLE_ONLY=0; SHARED_IDENTITY=0; KEEP_BG=0
WARN=0; ERRORS=0; REMOVED=0; FREED=0; USERS_DONE=0; LOCKED=0
LOG_DIR="/Library/Logs/ClearTeamsMac"
LOG_FILE=""
CONSOLE_USER=""; CONSOLE_UID=""

log() {
    lvl="$1"; shift
    line="[$(date '+%Y-%m-%d %H:%M:%S')] [$(printf '%-5s' "$lvl")] $*"
    echo "$line"
    [ -n "$LOG_FILE" ] && echo "$line" >> "$LOG_FILE" 2>/dev/null
    logger -t clearTeamsMac "$lvl: $*" 2>/dev/null
    case "$lvl" in WARN) WARN=$((WARN+1));; ERROR) ERRORS=$((ERRORS+1));; esac
    return 0
}

fmt() {
    b="${1:-0}"
    if   [ "$b" -ge 1073741824 ]; then echo "$((b/1073741824)) GB"
    elif [ "$b" -ge 1048576 ];    then echo "$((b/1048576)) MB"
    elif [ "$b" -ge 1024 ];       then echo "$((b/1024)) KB"
    else echo "${b} B"; fi
}

# --- watchdog: macOS has no timeout(1), and a locked keychain can block `security` forever ---
capped() {
    cap="$1"; shift
    "$@" </dev/null >/dev/null 2>&1 & wpid=$!
    t=0; max=$((cap*5))
    while kill -0 "$wpid" 2>/dev/null; do
        [ "$t" -ge "$max" ] && { kill -TERM "$wpid" 2>/dev/null; sleep 1; kill -KILL "$wpid" 2>/dev/null; return 124; }
        sleep 0.2; t=$((t+1))
    done
    wait "$wpid"; return $?
}

# --- safety guard: only ever inside a real user's home, and only Teams-related paths ---
safe() {
    p="${1%/}"; home="${2%/}"
    [ -n "$p" ] && [ -n "$home" ] || return 1
    case "$home" in /Users/*) : ;; *) [ "${PMC_ALLOW_NONSTANDARD_HOME:-0}" = "1" ] || return 1 ;; esac
    [ "$p" = "$home" ] && return 1
    case "$p" in "$home"/*) : ;; *) return 1 ;; esac
    case "$p" in *"/../"*|*"/.."|*"/./"*) return 1 ;; esac
    # Never user documents, never cloud-synced content, never other apps' mail data.
    for leaf in Documents Desktop Downloads Pictures Movies Music Public; do
        case "$p" in "$home/$leaf"|"$home/$leaf"/*) return 1 ;; esac
    done
    case "$p" in
        */Library/CloudStorage*|*/Library/Mobile?Documents*) return 1 ;;
        */UBF8T346G9.Office/*|*.olm|*.pst|*.olk15*|*.eml) return 1 ;;
        *Teams?Backgrounds?*preserved*) return 1 ;;
    esac
    return 0
}

wipe() {
    # wipe <path> <home> <description>
    p="$1"; home="$2"; d="$3"
    if [ ! -e "$p" ] && [ ! -L "$p" ]; then log SKIP "$d - not present."; return 0; fi
    if ! safe "$p" "$home"; then log ERROR "$d - REFUSED by safety guard: $p"; return 1; fi
    kb=$(du -sk "$p" 2>/dev/null | awk '{print $1+0; exit}')
    if [ "$DRY" = "1" ]; then log DRY "$d - WOULD remove $p ($(fmt $((kb*1024))))"; return 0; fi
    chflags -R nouchg "$p" 2>/dev/null
    if rm -rf "$p" 2>/dev/null && [ ! -e "$p" ]; then
        FREED=$((FREED + kb*1024)); REMOVED=$((REMOVED+1))
        log OK "$d - removed ($(fmt $((kb*1024))))"
    else
        log WARN "$d - could not fully remove (locked, or needs Full Disk Access)."
        LOCKED=1
    fi
    return 0
}

teams_running() {
    pgrep -x "MSTeams" >/dev/null 2>&1 && return 0
    pgrep -x "Microsoft Teams" >/dev/null 2>&1 && return 0
    pgrep -f "com.microsoft.teams2" >/dev/null 2>&1 && return 0
    return 1
}

quit_teams() {
    log STEP "--- Closing Teams ---"
    if [ "$DRY" = "1" ]; then log DRY "WOULD quit Microsoft Teams"; return 0; fi

    if [ "$FORCE" != "1" ] && [ -n "$CONSOLE_USER" ] && [ -n "$CONSOLE_UID" ]; then
        for app in "Microsoft Teams" "Microsoft Teams classic" "Microsoft Teams (work or school)"; do
            capped 12 launchctl asuser "$CONSOLE_UID" sudo -u "$CONSOLE_USER" \
                osascript -e "tell application \"$app\" to if it is running then quit"
        done
        w=0
        while [ "$w" -lt 20 ]; do teams_running || break; sleep 2; w=$((w+2)); done
    fi

    if teams_running; then
        pkill -TERM -x "MSTeams" 2>/dev/null
        pkill -TERM -f "com.microsoft.teams2" 2>/dev/null
        pkill -TERM -x "Microsoft Teams" 2>/dev/null
        sleep 3
        pkill -KILL -x "MSTeams" 2>/dev/null
        pkill -KILL -f "com.microsoft.teams2" 2>/dev/null
        pkill -KILL -x "Microsoft Teams" 2>/dev/null
        sleep 1
    fi

    if teams_running; then
        log WARN "Teams is still running - its files stay locked. Close it and re-run."
        return 1
    fi
    log OK "Teams is closed."
    return 0
}

save_backgrounds() {
    home="$1"; owner="$2"
    [ "$KEEP_BG" = "1" ] && return 0
    src="$home/Library/Containers/com.microsoft.teams2/Data/Library/Application Support/Microsoft/MSTeams/Backgrounds/Uploads"
    [ -d "$src" ] && [ -n "$(ls -A "$src" 2>/dev/null)" ] || return 0
    dest="$home/Teams Backgrounds (preserved)/$(date +%Y%m%d-%H%M%S)"
    if [ "$DRY" = "1" ]; then log DRY "WOULD preserve custom meeting backgrounds -> $dest"; return 0; fi
    if mkdir -p "$dest" 2>/dev/null && ditto "$src" "$dest" 2>/dev/null; then
        chown -R "$owner" "$home/Teams Backgrounds (preserved)" 2>/dev/null
        log OK "PRESERVED custom meeting backgrounds -> $dest"
    else
        log WARN "Could not preserve custom meeting backgrounds - continuing."
    fi
    return 0
}

clean_teams_files() {
    home="$1"; who="$2"
    log STEP "--- Teams files: $who ---"

    save_backgrounds "$home" "$who"

    # New Teams (2.x) - Microsoft's documented reset paths.
    wipe "$home/Library/Group Containers/UBF8T346G9.com.microsoft.teams" "$home" "New Teams group container"
    for id in com.microsoft.teams2 com.microsoft.teams2.launcher \
              com.microsoft.teams2.notificationcenter com.microsoft.teams2.respawn; do
        wipe "$home/Library/Containers/$id" "$home" "Container $id"
    done
    wipe "$home/Library/Application Scripts/com.microsoft.teams2" "$home" "Teams application scripts"

    # Classic Teams.
    wipe "$home/Library/Application Support/Microsoft/Teams" "$home" "Classic Teams data"
    wipe "$home/Library/Caches/com.microsoft.teams" "$home" "Classic Teams cache"

    # Web session material (Teams signs in through a webview).
    for p in "$home/Library/Caches"/com.microsoft.teams* \
             "$home/Library/HTTPStorages"/com.microsoft.teams* \
             "$home/Library/Cookies"/com.microsoft.teams*.binarycookies \
             "$home/Library/WebKit"/com.microsoft.teams* \
             "$home/Library/Saved Application State"/com.microsoft.teams*.savedState \
             "$home/Library/Preferences"/com.microsoft.teams*.plist; do
        [ -e "$p" ] || continue
        wipe "$p" "$home" "$(basename "$p")"
    done
    return 0
}

kc_del() {
    # kc_del <user> <uid> <keychain> <-l|-s> <value>
    u="$1"; uid="$2"; kc="$3"; sel="$4"; val="$5"
    # Never touch a browser's Safe Storage key - it would destroy saved browser passwords.
    case "$val" in *Chrome*|*Edge*|*Chromium*) log SKIP "Keychain: refusing '$val'."; return 0 ;; esac

    if [ "$DRY" = "1" ]; then
        if capped 15 launchctl asuser "$uid" sudo -u "$u" security find-generic-password "$sel" "$val" "$kc"; then
            log DRY "WOULD delete keychain item: $sel '$val'"
        fi
        return 0
    fi
    n=0
    while [ "$n" -lt 15 ]; do
        capped 15 launchctl asuser "$uid" sudo -u "$u" security delete-generic-password "$sel" "$val" "$kc"
        rc=$?
        if [ "$rc" = "124" ]; then
            log WARN "Keychain timed out on '$val' - the login keychain is probably locked."
            return 1
        fi
        [ "$rc" != "0" ] && break
        n=$((n+1))
    done
    [ "$n" -gt 0 ] && { REMOVED=$((REMOVED+n)); log OK "Keychain: deleted $n item(s) - $val"; }
    return 0
}

clean_teams_keychain() {
    u="$1"; uid="$2"; home="$3"
    kc="$home/Library/Keychains/login.keychain-db"
    [ -f "$kc" ] || { log WARN "login.keychain-db not found - keychain step skipped."; return 0; }

    log STEP "--- Teams keychain items: $u ---"
    capped 10 launchctl asuser "$uid" sudo -u "$u" security list-keychains -s "$kc"

    for l in "Microsoft Teams Identities Cache" \
             "Teams Safe Storage" \
             "Microsoft Teams (work or school) Safe Storage" \
             "teamsIv" "teamsKey"; do
        kc_del "$u" "$uid" "$kc" -l "$l" || return 0
    done

    if [ "$SHARED_IDENTITY" = "1" ]; then
        log WARN "--also-shared-identity: clearing the SHARED Microsoft sign-in broker."
        log WARN "  Word, Excel, Outlook and OneDrive will also ask for sign-in."
        wipe "$home/Library/Group Containers/UBF8T346G9.com.microsoft.oneauth" "$home" "Shared OneAuth broker store"
        kc_del "$u" "$uid" "$kc" -s "OneAuthAccount"
        kc2=$(find "$home/Library/Keychains" -maxdepth 2 -name "keychain-2.db" 2>/dev/null | head -1)
        if [ -n "$kc2" ] && [ "$DRY" != "1" ] && command -v sqlite3 >/dev/null 2>&1; then
            sqlite3 "$kc2" "DELETE FROM genp WHERE agrp='UBF8T346G9.com.microsoft.identity.universalstorage';" 2>/dev/null \
                && log OK "Shared account list purged - account pickers will be empty."
        fi
    else
        log INFO "Shared Office sign-in left intact (Word/Excel/Outlook stay signed in)."
        log INFO "  The account name may still show in the Teams picker; clicking it signs"
        log INFO "  in against the current tenant. Use --also-shared-identity to clear it."
    fi
    return 0
}

main() {
    exec </dev/null   # stdin is the script itself when piped from curl

    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run)              DRY=1; shift ;;
            --force)                FORCE=1; shift ;;
            --console-user-only)    CONSOLE_ONLY=1; shift ;;
            --also-shared-identity) SHARED_IDENTITY=1; shift ;;
            --keep-backgrounds)     KEEP_BG=1; shift ;;
            *) echo "Unknown flag: $1" >&2; shift ;;
        esac
    done

    mkdir -p "$LOG_DIR" 2>/dev/null || LOG_DIR="/tmp"
    LOG_FILE="$LOG_DIR/ClearTeamsMac-$(date +%Y%m%d-%H%M%S).log"
    : > "$LOG_FILE" 2>/dev/null || LOG_FILE=""

    log STEP "================================================================="
    log STEP " Microsoft Teams reset for macOS   v$VERSION"
    log STEP " Teams only - Outlook, Office, OneDrive and browsers untouched"
    log STEP "================================================================="

    [ "$(id -u)" = "0" ] || { log ERROR "Must run as root:  curl -fsSL <URL> | sudo bash -s --"; return 64; }
    [ "$DRY" = "1" ] && log DRY "DRY RUN - nothing will be changed."

    CONSOLE_USER=$(echo "show State:/Users/ConsoleUser" | scutil 2>/dev/null | awk '/Name :/ && ! /loginwindow/ {print $3; exit}')
    if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ]; then
        CONSOLE_UID=$(id -u "$CONSOLE_USER" 2>/dev/null)
        log INFO "Signed-in user : $CONSOLE_USER (uid $CONSOLE_UID)"
    else
        CONSOLE_USER=""
        log WARN "Nobody is signed in - keychain items can only be cleared for a signed-in user."
    fi

    if ! quit_teams; then
        log WARN "Stopping: Teams could not be closed. Nothing was changed."
        return 75
    fi

    if [ "$CONSOLE_ONLY" = "1" ]; then
        users="$CONSOLE_USER"
    else
        users=$(dscl . -list /Users UniqueID 2>/dev/null | awk '$2 >= 500 && $1 !~ /^_/ {print $1}')
    fi
    users=$(echo "$users" | awk 'NF' | sort -u)
    [ -n "$users" ] || { log ERROR "No user account found."; return 1; }

    while IFS= read -r U; do
        [ -n "$U" ] || continue
        H=$(dscl . -read "/Users/$U" NFSHomeDirectory 2>/dev/null | awk '{print $2; exit}')
        [ -n "$H" ] && [ -d "$H" ] || { log WARN "$U has no home directory - skipped."; continue; }
        case "$H" in /Users/*) : ;; *) [ "${PMC_ALLOW_NONSTANDARD_HOME:-0}" = "1" ] || { log WARN "$U home outside /Users - skipped."; continue; } ;; esac

        log STEP "#################################################################"
        log STEP " USER: $U   ($H)"
        log STEP "#################################################################"

        clean_teams_files "$H" "$U"

        if [ -n "$CONSOLE_USER" ] && [ "$U" = "$CONSOLE_USER" ]; then
            clean_teams_keychain "$U" "$CONSOLE_UID" "$H"
        else
            log INFO "$U is not signed in - keychain items left for a later run."
        fi
        USERS_DONE=$((USERS_DONE+1))
    done <<EOF_USERS
$users
EOF_USERS

    log STEP "================================================================="
    log INFO "Users processed  : $USERS_DONE"
    log INFO "Items removed    : $REMOVED"
    log INFO "Space reclaimed  : $(fmt "$FREED")"
    log INFO "Warnings         : $WARN     Errors: $ERRORS"
    [ "$LOCKED" = "1" ] && log WARN "Some files were locked - a restart will release them."
    log INFO "Log file         : ${LOG_FILE:-console only}"
    log STEP "================================================================="
    log INFO "Next: open Teams. It will show the sign-in screen. Sign in with the"
    log INFO "new tenant account. First launch is slower while the cache rebuilds."

    [ "$ERRORS" -gt 0 ] && return 1
    [ "$WARN" -gt 0 ] && return 1
    return 0
}

main "$@"; exit $?
} # ===== end truncation guard =====
