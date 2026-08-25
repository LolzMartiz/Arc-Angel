#!/bin/bash
{ # ===== TRUNCATION GUARD - do not remove. Forces bash to parse the whole script =====
  #       before executing anything, so a cut `curl | bash` download cannot run
  #       a half-command. The only call to main() is on the last line.

# =============================================================================================
#  clearCacheMac.sh   v3.0.0
#  Microsoft 365 tenant-to-tenant CREDENTIAL cleanup for macOS endpoints.
#
#  PURPOSE
#    Clear cached Microsoft sign-in credentials and tokens so Outlook, Teams, OneDrive,
#    Office and browsers re-authenticate against the NEW tenant instead of silently
#    reusing OLD tenant tokens.
#
#  ###########################################################################################
#  #  MAIL DATA IS NEVER TOUCHED.                                                            #
#  #                                                                                          #
#  #  Outlook for Mac keeps ALL mail in ONE place:                                            #
#  #    ~/Library/Group Containers/UBF8T346G9.Office/Outlook/Outlook 15 Profiles/<Profile>/   #
#  #  That single store holds the server cache AND "On My Computer" local-only folders AND    #
#  #  signatures, rules, categories and imported .olm archive content. They cannot be         #
#  #  separated at file level.                                                                #
#  #                                                                                          #
#  #  This script therefore NEVER reads, moves or deletes that path - not by default,         #
#  #  not under any flag. It is enforced by a hard deny-list inside the deletion guard,       #
#  #  so even a future edit that named the path by mistake would be refused and logged.       #
#  #  Mail files (.olm .pst .olk15* .eml .mbox) are denied by extension as a second layer.    #
#  #                                                                                          #
#  #  Outlook is signed out by clearing TOKENS ONLY (keychain + OneAuth + webview state).     #
#  ###########################################################################################
#
#  WHAT IS CLEARED
#    Outlook   : keychain credentials (Exchange/ADAL/Office identity), OneAuth token store,
#                container auth + webview state (cookies, WebKit, HTTPStorages, caches).
#                Profile, mail, signatures, rules and preferences all untouched.
#    Office    : identity/licence token caches, OneAuth, activation e-mail hint.
#    Teams      : caches and token containers (custom meeting backgrounds are rescued first).
#    OneDrive  : account link/settings only - never synced files. Gated: skipped when Known
#                Folder Move is active or online-only files are present (see --force-onedrive).
#    Browsers  : Chrome / Edge / Safari sign-out. Default clears cookies+site storage for all
#                sites; --browsers microsoft narrows it to Microsoft domains only.
#    Work acct : Workplace-Join keychain entries + MS-Organization-Access device identity.
#    MDM       : detected and REPORTED only. Never unenrolled.
#
#  AFTER THIS SCRIPT RUNS - ONE MANUAL STEP IN OUTLOOK
#    Because the profile is preserved, the OLD account is still listed in Outlook and will
#    keep prompting. The user (or tech) must remove it:
#         Outlook > Tools > Accounts > select old account > Manage > REMOVE ACCOUNT
#    *** Use "Remove Account". NEVER use "Reset Account" - that menu item sits directly ***
#    *** beside it and Microsoft documents it as deleting everything not on the server,  ***
#    *** which means it DOES destroy "On My Computer" mail.                              ***
#    Removing the ACCOUNT keeps "On My Computer" folders intact (they are profile-level).
#
#  USAGE (flags go after `bash -s --` when piping from curl)
#    curl -fsSL <RAW_URL> | sudo bash -s -- --dry-run
#    curl -fsSL <RAW_URL> | sudo bash -s --
#    curl -fsSL <RAW_URL> | sudo bash -s -- --browsers microsoft --force
#
#    Two-step is safer for production (protects against truncated downloads):
#    curl -fsSL --retry 3 --max-time 60 -o /tmp/cc.sh <RAW_URL> && sudo bash /tmp/cc.sh
#
#  FLAGS
#    --dry-run              Report every action. Change nothing. Run this first.
#    --force                Force-quit apps instead of deferring when they are open.
#    --grace N              Seconds to wait for a graceful quit (default 45).
#    --console-user-only    Only process the signed-in user (default: all local users).
#    --browsers MODE        all (default) | microsoft | none
#                             all       - clear cookies + site storage for every site
#                                         (signs the user out of non-Microsoft sites too)
#                             microsoft - surgical: only Microsoft cookies and Microsoft
#                                         site storage. NOTE: may leave Teams/Outlook web
#                                         signed in, because browser Local Storage cannot
#                                         be filtered per site with standard tooling.
#                             none      - skip browsers entirely
#    --skip-onedrive        Do not touch the OneDrive account link.
#    --force-onedrive       Unlink OneDrive even when KFM / online-only files are detected.
#    --skip-keychain        Do not touch the keychain.
#    --skip-workaccount     Do not remove work-account / Workplace-Join material.
#    --skip-teams           Do not touch Teams.
#    --reset-outlook-prefs  ALSO reset Outlook's preference plist (window layout, view
#                           settings, notification prefs). Still no mail. Off by default.
#    --log-dir PATH         Default /Library/Logs/PostMigrationCleanup
#
#  EXIT CODES (chosen so an RMM can distinguish "retry later" from "broken")
#    0   completed
#    1   completed with warnings (see log)
#    2   fatal error
#    64  bad invocation / not root
#    75  DEFERRED - retry later (no console user, apps still open, another run in progress)
#    77  TCC/Full Disk Access denied - grant FDA to the RMM agent via MDM PPPC, then re-run
# =============================================================================================

# --- Deterministic environment. launchctl asuser sets no PATH; never rely on inheritance.
#     PMC_PATH_PREFIX is a test hook only - unset in production, so PATH is fixed. ---
PATH="${PMC_PATH_PREFIX:+$PMC_PATH_PREFIX:}/usr/bin:/bin:/usr/sbin:/sbin"
export PATH
set -u

SCRIPT_VERSION="3.1.0"

# =============================================================================================
#  DEFAULTS
# =============================================================================================
SCOPE_DRY=0
FORCE=0
GRACE=45
CONSOLE_ONLY=0
BROWSER_MODE="all"
SKIP_ONEDRIVE=0
FORCE_ONEDRIVE=0
SKIP_KEYCHAIN=0
SKIP_WORKACCOUNT=0
SKIP_TEAMS=0
RESET_OUTLOOK_PREFS=0
LOG_DIR="/Library/Logs/PostMigrationCleanup"

# Runtime state
WARN_COUNT=0
ERROR_COUNT=0
ITEMS_REMOVED=0
BYTES_FREED=0
RESTART_RECOMMENDED=0
PROCESSED_USERS=0
DEFERRED=0
TCC_DENIED=0
START_EPOCH=$(date +%s)
HOSTNAME_SHORT=$(hostname -s 2>/dev/null || echo "unknown-mac")
LOG_FILE=""
RECEIPT_FILE=""
CONSOLE_USER=""
CONSOLE_UID=""
LOCK_DIR="/var/run/com.mitigata.clearCacheMac.lock"
LOCK_HELD=0
BACKUP_ROOT=""

# Microsoft domains used for surgical browser cleanup.
MS_COOKIE_DOMAINS="microsoftonline.com microsoft.com microsoftonline-p.com office.com office365.com
sharepoint.com live.com windows.net azure.com msauth.net msftauth.net msidentity.com
office.net outlook.com teams.microsoft.com onedrive.com msn.com skype.com"

# =============================================================================================
#  LOGGING
# =============================================================================================
init_logging() {
    if ! mkdir -p "$LOG_DIR" 2>/dev/null; then
        LOG_DIR="/tmp/PostMigrationCleanup"
        mkdir -p "$LOG_DIR" 2>/dev/null
    fi
    stamp=$(date +%Y%m%d-%H%M%S)
    LOG_FILE="$LOG_DIR/PostMigrationCleanup-$HOSTNAME_SHORT-$stamp.log"
    RECEIPT_FILE="$LOG_DIR/receipt-$HOSTNAME_SHORT-$stamp.json"
    : > "$LOG_FILE" 2>/dev/null || LOG_FILE=""
}

log() {
    level="$1"; shift
    line="[$(date '+%Y-%m-%d %H:%M:%S')] [$(printf '%-5s' "$level")] $*"
    echo "$line"
    [ -n "$LOG_FILE" ] && echo "$line" >> "$LOG_FILE" 2>/dev/null
    # Unified log, so the run is retrievable even if the file is lost.
    logger -t "clearCacheMac" "$level: $*" 2>/dev/null
    case "$level" in
        WARN)  WARN_COUNT=$((WARN_COUNT + 1)) ;;
        ERROR) ERROR_COUNT=$((ERROR_COUNT + 1)) ;;
    esac
    return 0
}

fmt_bytes() {
    b="${1:-0}"
    if   [ "$b" -ge 1073741824 ]; then echo "$((b / 1073741824)) GB"
    elif [ "$b" -ge 1048576 ];    then echo "$((b / 1048576)) MB"
    elif [ "$b" -ge 1024 ];       then echo "$((b / 1024)) KB"
    else echo "${b} B"; fi
}

# =============================================================================================
#  WATCHDOG
#  macOS ships no timeout(1). Any `security` call made inside a user GUI session can block
#  forever on a SecurityAgent unlock dialog (locked login keychain / keychain password out of
#  sync after a tenant move). Every keychain and AppleScript call goes through this.
# =============================================================================================
run_capped() {
    # run_capped <seconds> <command...>   -> returns cmd status, or 124 on timeout
    cap="$1"; shift
    "$@" </dev/null >/dev/null 2>&1 &
    wpid=$!
    # Poll at 0.2s so a fast command (the normal case) costs almost nothing, while the
    # cap is still expressed in whole seconds.
    ticks=0
    maxticks=$((cap * 5))
    while kill -0 "$wpid" 2>/dev/null; do
        if [ "$ticks" -ge "$maxticks" ]; then
            kill -TERM "$wpid" 2>/dev/null
            sleep 1
            kill -KILL "$wpid" 2>/dev/null
            return 124
        fi
        sleep 0.2
        ticks=$((ticks + 1))
    done
    wait "$wpid"
    return $?
}

# =============================================================================================
#  SAFETY GUARD
#  Every single deletion in this script passes through path_is_safe() first.
# =============================================================================================

# Absolute deny-list. These patterns can never be deleted, regardless of caller or flag.
path_is_denied() {
    p="$1"
    case "$p" in
        # ---- OUTLOOK MAIL DATA: the whole reason this version exists ----
        */Group?Containers/UBF8T346G9.Office/Outlook|*/Group?Containers/UBF8T346G9.Office/Outlook/*)
            return 0 ;;
        */Group?Containers/UBF8T346G9.Office/OutlookProfile.plist)
            return 0 ;;
        *Outlook?15?Profiles*|*Outlook?14?Profiles*)
            return 0 ;;
        # ---- Mail data by file type, at any location ----
        *.olm|*.pst|*.ost|*.mbox|*.eml|*.emlx|*.olk15*|*.olk14*)
            return 0 ;;
        # ---- Cloud-synced content and macOS-owned sync roots ----
        */Library/CloudStorage|*/Library/CloudStorage/*)
            return 0 ;;
        */Library/Mobile?Documents|*/Library/Mobile?Documents/*)
            return 0 ;;
        # ---- Our own backups ----
        *M365?Cleanup?Backups*|*Outlook?Archives?*preserved*)
            return 0 ;;
        # ---- Browser credential material: deleting these makes every saved password
        #      in that browser permanently undecryptable ----
        *Safe?Storage*)
            return 0 ;;
    esac
    return 1
}

path_is_safe() {
    # path_is_safe <path> <user_home>
    p="$1"; home="$2"

    [ -n "$p" ] || return 1
    [ -n "$home" ] || return 1
    [ "$home" != "/" ] || return 1

    case "$home" in
        /Users/*) : ;;
        *) [ "${PMC_ALLOW_NONSTANDARD_HOME:-0}" = "1" ] || return 1 ;;
    esac

    p="${p%/}"; home="${home%/}"
    [ -n "$p" ] || return 1

    # Absolute deny-list first.
    if path_is_denied "$p"; then
        return 1
    fi

    # Must be strictly inside the user's home, and not the home itself.
    [ "$p" = "$home" ] && return 1
    case "$p" in
        "$home"/*) : ;;
        *) return 1 ;;
    esac

    # No traversal tricks.
    case "$p" in
        *"/../"*|*"/.."|*"/./"*) return 1 ;;
    esac

    # Never inside user document folders.
    for leaf in Documents Desktop Downloads Pictures Movies Music Public Applications; do
        case "$p" in
            "$home/$leaf"|"$home/$leaf"/*) return 1 ;;
        esac
    done

    # Never inside a legacy OneDrive sync folder.
    case "$p" in
        "$home/OneDrive"*) return 1 ;;
    esac

    return 0
}

# =============================================================================================
#  FILESYSTEM HELPERS
# =============================================================================================
folder_size_kb() {
    [ -e "$1" ] || { echo 0; return; }
    du -sk "$1" 2>/dev/null | awk '{print $1+0; exit}'
}

# Detects a TCC denial rather than reporting a false success.
tcc_check() {
    # tcc_check <path>  -> 0 = readable, 1 = blocked by privacy protection
    [ -e "$1" ] || return 0
    if ls "$1" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

remove_path() {
    # remove_path <path> <user_home> <description>
    p="$1"; home="$2"; desc="$3"

    if [ ! -e "$p" ] && [ ! -L "$p" ]; then
        log SKIP "$desc - not present."
        return 0
    fi
    if ! path_is_safe "$p" "$home"; then
        if path_is_denied "$p"; then
            log ERROR "$desc - REFUSED: protected data path (deny-list): $p"
        else
            log ERROR "$desc - REFUSED by safety guard: $p"
        fi
        return 1
    fi

    kb=$(folder_size_kb "$p")
    if [ "$SCOPE_DRY" = "1" ]; then
        log DRY "$desc - WOULD remove $p ($(fmt_bytes $((kb * 1024))))"
        return 0
    fi

    chflags -R nouchg "$p" 2>/dev/null
    if rm -rf "$p" 2>/dev/null && [ ! -e "$p" ]; then
        BYTES_FREED=$((BYTES_FREED + kb * 1024))
        ITEMS_REMOVED=$((ITEMS_REMOVED + 1))
        log OK "$desc - removed ($(fmt_bytes $((kb * 1024))))"
    else
        if ! tcc_check "$p"; then
            TCC_DENIED=1
            log WARN "$desc - blocked by macOS privacy protection (needs Full Disk Access)."
        else
            log WARN "$desc - could not fully remove (locked by a running process)."
            RESTART_RECOMMENDED=1
        fi
    fi
    return 0
}

clear_folder() {
    # clear_folder <path> <user_home> <description>   - empties, keeps the folder
    p="$1"; home="$2"; desc="$3"

    if [ ! -d "$p" ]; then
        log SKIP "$desc - not present."
        return 0
    fi
    if ! path_is_safe "$p" "$home"; then
        if path_is_denied "$p"; then
            log ERROR "$desc - REFUSED: protected data path (deny-list): $p"
        else
            log ERROR "$desc - REFUSED by safety guard: $p"
        fi
        return 1
    fi

    kb=$(folder_size_kb "$p")
    if [ "$SCOPE_DRY" = "1" ]; then
        log DRY "$desc - WOULD clear $p ($(fmt_bytes $((kb * 1024))))"
        return 0
    fi

    chflags -R nouchg "$p" 2>/dev/null
    find "$p" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null

    leftover=$(find "$p" -mindepth 1 -maxdepth 1 2>/dev/null | head -1)
    if [ -z "$leftover" ]; then
        BYTES_FREED=$((BYTES_FREED + kb * 1024))
        ITEMS_REMOVED=$((ITEMS_REMOVED + 1))
        log OK "$desc - cleared ($(fmt_bytes $((kb * 1024))))"
    else
        BYTES_FREED=$((BYTES_FREED + kb * 1024))
        if ! tcc_check "$p"; then
            TCC_DENIED=1
            log WARN "$desc - blocked by macOS privacy protection (needs Full Disk Access)."
        else
            log WARN "$desc - partially cleared, some items still locked. Restart releases them."
            RESTART_RECOMMENDED=1
        fi
    fi
    return 0
}

backup_dir_for() {
    # backup_dir_for <user_home> <owner>  -> echoes a per-run backup folder, creating it
    bhome="$1"; bowner="$2"
    if [ -z "$BACKUP_ROOT" ]; then
        BACKUP_ROOT="M365 Cleanup Backups/$(date +%Y%m%d-%H%M%S)"
    fi
    bd="$bhome/$BACKUP_ROOT"
    mkdir -p "$bd" 2>/dev/null && chown "$bowner" "$bhome/M365 Cleanup Backups" "$bd" 2>/dev/null
    echo "$bd"
}

# =============================================================================================
#  USER / SESSION RESOLUTION
# =============================================================================================
get_console_user() {
    u=$(echo "show State:/Users/ConsoleUser" | scutil 2>/dev/null | awk '/Name :/ && ! /loginwindow/ { print $3; exit }')
    if [ -n "$u" ] && [ "$u" != "root" ] && [ "$u" != "loginwindow" ]; then
        CONSOLE_USER="$u"
        CONSOLE_UID=$(id -u "$u" 2>/dev/null || echo "")
    fi
}

list_local_users() {
    dscl . -list /Users UniqueID 2>/dev/null | awk '$2 >= 500 && $1 !~ /^_/ {print $1}'
}

user_home() {
    dscl . -read "/Users/$1" NFSHomeDirectory 2>/dev/null | awk '{print $2; exit}'
}

run_as_user() {
    # run_as_user <user> <uid> <command...>  - inside the user's GUI/bootstrap session.
    ru="$1"; ruid="$2"; shift 2
    launchctl asuser "$ruid" sudo -u "$ru" "$@" 2>/dev/null
}

run_as_user_capped() {
    # Same, but watchdogged. Use for anything that can raise a GUI prompt.
    ru="$1"; ruid="$2"; cap="$3"; shift 3
    run_capped "$cap" launchctl asuser "$ruid" sudo -u "$ru" "$@"
}

# =============================================================================================
#  APPLICATION SHUTDOWN
#  Microsoft's own tooling refuses to run while Office apps are open. We mirror that:
#  defer by default, force only on request. Killing Outlook mid-write is the one action in
#  this whole script that could damage the mail store, so it is never done casually.
# =============================================================================================
ms_procs_running() {
    pgrep -x "Microsoft Outlook" >/dev/null 2>&1 && return 0
    pgrep -x "Microsoft Word" >/dev/null 2>&1 && return 0
    pgrep -x "Microsoft Excel" >/dev/null 2>&1 && return 0
    pgrep -x "Microsoft PowerPoint" >/dev/null 2>&1 && return 0
    pgrep -x "MSTeams" >/dev/null 2>&1 && return 0
    pgrep -x "OneDrive" >/dev/null 2>&1 && return 0
    return 1
}

browsers_running() {
    pgrep -x "Google Chrome" >/dev/null 2>&1 && return 0
    pgrep -x "Microsoft Edge" >/dev/null 2>&1 && return 0
    pgrep -x "Safari" >/dev/null 2>&1 && return 0
    return 1
}

quit_apps() {
    log STEP "--- Closing applications ---"

    gui_apps="Microsoft Outlook|Microsoft Word|Microsoft Excel|Microsoft PowerPoint|Microsoft OneNote|Microsoft Teams|OneDrive|Company Portal"
    if [ "$BROWSER_MODE" != "none" ]; then
        gui_apps="$gui_apps|Safari|Google Chrome|Microsoft Edge"
    fi

    if [ "$SCOPE_DRY" = "1" ]; then
        log DRY "WOULD ask these to quit: $(echo "$gui_apps" | tr '|' ' ')"
        return 0
    fi

    # Phase 1 - polite quit inside the user session. `quit` needs no AppleEvents consent.
    if [ -n "$CONSOLE_USER" ] && [ -n "$CONSOLE_UID" ]; then
        echo "$gui_apps" | tr '|' '\n' | while IFS= read -r app; do
            [ -n "$app" ] || continue
            run_as_user_capped "$CONSOLE_USER" "$CONSOLE_UID" 15 \
                osascript -e "tell application \"$app\" to if it is running then quit"
        done
        log INFO "Graceful quit requested. Waiting up to ${GRACE}s for apps to flush and exit..."
        waited=0
        while [ "$waited" -lt "$GRACE" ]; do
            if ! ms_procs_running && ! browsers_running; then break; fi
            sleep 3; waited=$((waited + 3))
        done
    fi

    # Phase 2 - still open? Defer unless forced. An unsaved-changes dialog blocks `quit`
    # forever, so this is the normal case on a machine someone is actively using.
    if ms_procs_running || browsers_running; then
        if [ "$FORCE" != "1" ]; then
            log WARN "Applications are still open (likely an unsaved-work dialog)."
            log WARN "DEFERRING rather than force-killing: killing Outlook mid-write risks its"
            log WARN "mail database. Ask the user to save and close, or re-run with --force."
            DEFERRED=1
            return 1
        fi

        log WARN "--force supplied: terminating applications. Unsaved work will be lost."
        echo "$gui_apps" | tr '|' '\n' | while IFS= read -r app; do
            [ -n "$app" ] || continue
            pkill -TERM -x "$app" 2>/dev/null
        done
        pkill -TERM -f "com.microsoft.teams2" 2>/dev/null
        sleep 5
        echo "$gui_apps" | tr '|' '\n' | while IFS= read -r app; do
            [ -n "$app" ] || continue
            pkill -KILL -x "$app" 2>/dev/null
        done
        pkill -KILL -f "com.microsoft.teams2" 2>/dev/null
        sleep 2
        log WARN "Applications force-terminated (recorded for traceability)."
    else
        log OK "All target applications closed cleanly."
    fi
    return 0
}

check_outlook_store_clean() {
    # Report-only integrity signal: a leftover -wal beside the store means Outlook did not
    # close cleanly. We never touch these files; this is purely so a later problem report
    # is attributable.
    home="$1"
    d="$home/Library/Group Containers/UBF8T346G9.Office/Outlook"
    [ -d "$d" ] || return 0
    wal=$(find "$d" -name "*.sqlite-wal" -maxdepth 4 2>/dev/null | head -1)
    if [ -n "$wal" ]; then
        log WARN "Outlook store has an open write-ahead log - it did not shut down cleanly."
        log WARN "Launch Outlook once and quit it normally before any further maintenance."
    fi
    return 0
}

# =============================================================================================
#  PRE-FLIGHT INVENTORY (report only - touches nothing)
# =============================================================================================
preflight_report() {
    home="$1"; uname_="$2"
    log STEP "--- Pre-flight inventory (nothing is modified here): $uname_ ---"

    prof="$home/Library/Group Containers/UBF8T346G9.Office/Outlook"
    if [ -d "$prof" ]; then
        # Deliberately NOT measured: a large mailbox (100 GB+) takes minutes to size, and
        # we never touch it anyway, so there is nothing to gain from scanning it.
        log INFO "Outlook mail store present - PROTECTED, will not be touched."
        omc=$(find "$prof" -maxdepth 3 -type d -name "Omc" 2>/dev/null | head -1)
        [ -n "$omc" ] && log INFO "  'On My Computer' local mail detected (new Outlook Omc store) - PROTECTED."
        nprof=$(find "$prof" -maxdepth 2 -type d -name "*Profiles" 2>/dev/null | head -1)
        [ -n "$nprof" ] && log INFO "  Profile folder: $(basename "$nprof") - PROTECTED."
    else
        log INFO "No Outlook mail store on disk for this user."
    fi

    # Loose archive files the user may care about. Only scanned during --dry-run: walking a
    # large home directory is slow and this is purely informational (the deny-list protects
    # these files regardless of whether we list them).
    if [ "$SCOPE_DRY" != "1" ]; then
        log INFO "Mail archives (.olm/.pst) are protected by the deny-list; scan skipped for speed."
        return 0
    fi
    n=$(find "$home" -maxdepth 4 \( -iname "*.olm" -o -iname "*.pst" \) 2>/dev/null | head -20 | wc -l | tr -d ' ')
    if [ "${n:-0}" -gt 0 ]; then
        log INFO "$n mail archive file(s) found in this home - PROTECTED by deny-list:"
        find "$home" -maxdepth 4 \( -iname "*.olm" -o -iname "*.pst" \) 2>/dev/null | head -20 |
            while IFS= read -r f; do log INFO "    $f"; done
    fi
    return 0
}

# =============================================================================================
#  OUTLOOK - CREDENTIALS ONLY
# =============================================================================================
clean_outlook_credentials() {
    home="$1"; uname_="$2"
    log STEP "--- Outlook credential cache (mail data untouched): $uname_ ---"

    ct="$home/Library/Containers/com.microsoft.Outlook/Data/Library"

    # Per-app identity / licensing state. Microsoft's own reset tooling treats this path
    # as credentials, never as data.
    remove_path "$ct/Application Support/Microsoft" "$home" "Outlook cached identity/licence state"

    # Webview + auth-flow state: this is what pins a stale tenant sign-in page.
    clear_folder "$ct/Caches"       "$home" "Outlook caches"
    clear_folder "$ct/Cookies"      "$home" "Outlook auth cookies"
    clear_folder "$ct/HTTPStorages" "$home" "Outlook HTTP storage"
    clear_folder "$ct/WebKit"       "$home" "Outlook webview storage (sign-in page state)"
    clear_folder "$ct/Saved Application State" "$home" "Outlook saved window state"

    # Add-in webview cache (shares the sign-in session).
    remove_path "$home/Library/Containers/com.Microsoft.OsfWebHost/Data/Library/Cookies" \
                "$home" "Office add-in webview cookies"

    if [ "$RESET_OUTLOOK_PREFS" = "1" ]; then
        log WARN "--reset-outlook-prefs: clearing Outlook preferences (layout/view settings)."
        remove_path "$ct/Preferences/com.microsoft.Outlook.plist" "$home" "Outlook preferences plist"
        remove_path "$home/Library/Preferences/com.microsoft.Outlook.plist" "$home" "Outlook preferences (legacy path)"
    else
        log INFO "Outlook preferences preserved (use --reset-outlook-prefs to reset them too)."
    fi

    log OK "Outlook credentials cleared. Mail store, profile and signatures untouched."
    log INFO "NEXT STEP for the user: Outlook > Tools > Accounts > old account > Manage >"
    log INFO "  'Remove Account'.  Do NOT choose 'Reset Account' - that deletes local mail."
    return 0
}

# =============================================================================================
#  OFFICE IDENTITY / LICENCE TOKENS
# =============================================================================================
clean_office() {
    home="$1"; uname_="$2"
    log STEP "--- Office identity and token caches: $uname_ ---"

    gc="$home/Library/Group Containers"
    ct="$home/Library/Containers"

    # OneAuth / MSAL broker store - the cached account list every Office app reads.
    remove_path "$gc/UBF8T346G9.com.microsoft.oneauth" "$home" "OneAuth token/account store"
    remove_path "$home/Library/Application Scripts/UBF8T346G9.com.microsoft.oneauth" "$home" "OneAuth application scripts"

    # Licence and identity state (siblings of the Outlook folder - never the Outlook folder).
    remove_path "$gc/UBF8T346G9.Office/Licenses"   "$home" "Office licence token cache"
    remove_path "$gc/UBF8T346G9.Office/Identity"   "$home" "Office identity store"
    remove_path "$gc/UBF8T346G9.Office/mip_policy" "$home" "Office sensitivity-label cache"
    remove_path "$gc/UBF8T346G9.Office/DRM_Evo.plist" "$home" "Office RMS cache"
    remove_path "$gc/UBF8T346G9.Office/com.microsoft.Office365.plist"   "$home" "Office 365 licensing plist"
    remove_path "$gc/UBF8T346G9.Office/com.microsoft.Office365V2.plist" "$home" "Office 365 licensing plist (V2)"

    remove_path "$ct/com.microsoft.Office365ServiceV2" "$home" "Office licensing helper container"
    remove_path "$ct/com.microsoft.RMS-XPCService"     "$home" "RMS XPC service container"

    # Per-app caches only - never AutoRecovery, never Preferences.
    for appid in com.microsoft.Word com.microsoft.Excel com.microsoft.Powerpoint com.microsoft.onenote.mac; do
        clear_folder "$ct/$appid/Data/Library/Caches" "$home" "$appid cache"
    done

    remove_path "$home/Library/Preferences/com.microsoft.msa-login-hint.plist" "$home" "MSA login hint"
    return 0
}

clean_office_prefs_userctx() {
    uname_="$1"; uid_="$2"
    [ -n "$uid_" ] || return 0
    if [ "$SCOPE_DRY" = "1" ]; then
        log DRY "WOULD clear the cached activation e-mail and stage ResetOneAuthCreds"
        return 0
    fi
    # Removes the pre-filled OLD tenant address from the sign-in sheet.
    run_as_user_capped "$uname_" "$uid_" 20 defaults delete com.microsoft.office OfficeActivationEmailAddress
    # Microsoft-documented OneAuth reset, consumed at next app launch.
    for dom in com.microsoft.Word com.microsoft.Excel com.microsoft.Powerpoint com.microsoft.Outlook; do
        run_as_user_capped "$uname_" "$uid_" 20 defaults write "$dom" ResetOneAuthCreds -bool YES
    done
    run_as_user_capped "$uname_" "$uid_" 15 killall cfprefsd
    log OK "Cached activation address cleared; OneAuth reset staged for next app launch."
    return 0
}

# =============================================================================================
#  TEAMS
# =============================================================================================
clean_teams() {
    home="$1"; uname_="$2"
    if [ "$SKIP_TEAMS" = "1" ]; then
        log SKIP "Teams cleanup skipped (--skip-teams)."
        return 0
    fi
    log STEP "--- Microsoft Teams: $uname_ ---"

    gc="$home/Library/Group Containers"
    ct="$home/Library/Containers"

    # Rescue user-uploaded custom meeting backgrounds - Microsoft warns that clearing the
    # Teams cache deletes personalisation, and these are genuinely the user's own files.
    bgsrc="$ct/com.microsoft.teams2/Data/Library/Application Support/Microsoft/MSTeams/Backgrounds/Uploads"
    if [ -d "$bgsrc" ] && [ -n "$(ls -A "$bgsrc" 2>/dev/null)" ]; then
        if [ "$SCOPE_DRY" = "1" ]; then
            log DRY "WOULD preserve custom Teams backgrounds from $bgsrc"
        else
            bd=$(backup_dir_for "$home" "$uname_")
            if [ -n "$bd" ] && mkdir -p "$bd/Teams Backgrounds" 2>/dev/null &&
               ditto "$bgsrc" "$bd/Teams Backgrounds" 2>/dev/null; then
                chown -R "$uname_" "$bd" 2>/dev/null
                log OK "PRESERVED custom Teams backgrounds -> $bd/Teams Backgrounds"
            else
                log WARN "Could not preserve custom Teams backgrounds - continuing."
            fi
        fi
    fi

    remove_path "$gc/UBF8T346G9.com.microsoft.teams" "$home" "New Teams group container"
    # Delete the Data folder inside each container, NOT the container itself. Every app
    # container holds a .com.apple.containermanagerd.metadata.plist that macOS protects -
    # even root cannot remove it - so deleting the container root always logs a scary
    # "Operation not permitted". Targeting Data removes all Teams state with no error.
    for tid in com.microsoft.teams2 com.microsoft.teams2.launcher com.microsoft.teams2.notificationcenter com.microsoft.teams2.respawn; do
        if [ -d "$ct/$tid" ]; then
            remove_path "$ct/$tid/Data" "$home" "Teams container data ($tid)"
        else
            log SKIP "Teams container $tid - not present."
        fi
    done
    remove_path "$home/Library/Application Support/Microsoft/Teams" "$home" "Classic Teams cache"
    remove_path "$home/Library/Caches/com.microsoft.teams" "$home" "Classic Teams cache folder"
    for ss in "$home/Library/Saved Application State"/com.microsoft.teams*.savedState; do
        [ -e "$ss" ] || continue
        remove_path "$ss" "$home" "Teams saved state $(basename "$ss")"
    done
    return 0
}

# =============================================================================================
#  ONEDRIVE  (gated - see the two hazards below)
# =============================================================================================
onedrive_kfm_active() {
    home="$1"
    for f in Desktop Documents; do
        t=$(readlink "$home/$f" 2>/dev/null)
        case "$t" in *CloudStorage*|*OneDrive*) return 0 ;; esac
        rp=$(cd "$home/$f" 2>/dev/null && pwd -P 2>/dev/null)
        case "$rp" in *CloudStorage*|*OneDrive*) return 0 ;; esac
    done
    return 1
}

onedrive_has_online_only() {
    home="$1"
    root=$(find "$home/Library/CloudStorage" -maxdepth 1 -type d -name "OneDrive*" 2>/dev/null | head -1)
    [ -n "$root" ] || return 1
    # Online-only placeholders carry the dataless flag. Best-effort, capped.
    hit=$(find "$root" -maxdepth 3 -flags +dataless -print 2>/dev/null | head -1)
    [ -n "$hit" ] && return 0
    return 1
}

clean_onedrive() {
    home="$1"; uname_="$2"
    if [ "$SKIP_ONEDRIVE" = "1" ]; then
        log SKIP "OneDrive unlink skipped (--skip-onedrive)."
        return 0
    fi
    log STEP "--- OneDrive account unlink: $uname_ ---"

    # HAZARD 1: Known Folder Move. If Desktop/Documents are redirected into the old
    # tenant's sync root, unlinking makes them appear empty to the user.
    if onedrive_kfm_active "$home"; then
        log WARN "Known Folder Move is ACTIVE - Desktop/Documents are redirected into OneDrive."
        if [ "$FORCE_ONEDRIVE" != "1" ]; then
            log WARN "SKIPPING OneDrive unlink: unlinking now would make the user's Desktop and"
            log WARN "Documents appear empty. Turn Folder Backup off in OneDrive settings first"
            log WARN "(Settings > Sync and backup > Manage backup), or re-run with --force-onedrive."
            return 0
        fi
        log WARN "--force-onedrive supplied: proceeding despite active Known Folder Move."
    fi

    # HAZARD 2: online-only files. They exist only in the cloud; if the OLD tenant is being
    # decommissioned, unlinking removes the user's only route to them.
    if onedrive_has_online_only "$home"; then
        log WARN "Online-only (cloud-only) OneDrive files detected on this Mac."
        if [ "$FORCE_ONEDRIVE" != "1" ]; then
            log WARN "SKIPPING OneDrive unlink: these files have no local copy. Confirm they exist"
            log WARN "in the NEW tenant (or download them first), then re-run with --force-onedrive."
            return 0
        fi
        log WARN "--force-onedrive supplied: proceeding despite online-only files."
    fi

    log INFO "Synced FILES are never touched - only the account link and settings."
    log INFO "The CloudStorage sync root is macOS-owned and is on the deny-list."

    clear_folder "$home/Library/Application Support/OneDrive/settings" "$home" "OneDrive settings (standalone)"
    clear_folder "$home/Library/Containers/com.microsoft.OneDrive-mac/Data/Library/Application Support/OneDrive/settings" \
                 "$home" "OneDrive settings (App Store build)"
    remove_path "$home/Library/Group Containers/UBF8T346G9.OneDriveStandaloneSuite"      "$home" "OneDrive standalone state"
    remove_path "$home/Library/Group Containers/UBF8T346G9.OneDriveSyncClientSuite"      "$home" "OneDrive sync client state"
    remove_path "$home/Library/Group Containers/UBF8T346G9.OfficeOneDriveSyncIntegration" "$home" "OneDrive/Office integration state"
    remove_path "$home/Library/Caches/com.microsoft.OneDrive" "$home" "OneDrive cache"
    log INFO "OneDrive will show first-run setup at next launch."
    return 0
}

# =============================================================================================
#  COMPANY PORTAL / WORK ACCOUNT FILES
# =============================================================================================
clean_company_portal() {
    home="$1"; uname_="$2"
    if [ "$SKIP_WORKACCOUNT" = "1" ]; then
        return 0
    fi
    log STEP "--- Company Portal / work account files: $uname_ ---"
    remove_path "$home/Library/Application Support/com.microsoft.CompanyPortalMac" "$home" "Company Portal app data"
    remove_path "$home/Library/Application Support/com.microsoft.CompanyPortalMac.usercontext.info" "$home" "Company Portal user context"
    remove_path "$home/Library/Application Support/com.microsoft.CompanyPortal" "$home" "Company Portal app data (legacy)"
    remove_path "$home/Library/Preferences/com.microsoft.CompanyPortalMac.plist" "$home" "Company Portal preferences"
    remove_path "$home/Library/Caches/com.microsoft.CompanyPortalMac" "$home" "Company Portal cache"
    remove_path "$home/Library/Caches/CompanyPortalCache" "$home" "Company Portal token cache"
    for ck in "$home/Library/Cookies"/com.microsoft.CompanyPortal*.binarycookies; do
        [ -e "$ck" ] || continue
        remove_path "$ck" "$home" "Company Portal cookies"
    done
    remove_path "$home/Library/Keychains/Microsoft_Entity_Certificates-db" "$home" "Microsoft entity certificates keychain"
    return 0
}

# =============================================================================================
#  BROWSERS
# =============================================================================================
chromium_ms_cookies() {
    # Surgical: delete only Microsoft-domain rows from a Chromium cookie DB.
    db="$1"; label="$2"; home="$3"
    [ -f "$db" ] || return 0

    if ! command -v sqlite3 >/dev/null 2>&1; then
        log WARN "$label - sqlite3 unavailable; cannot filter cookies by domain."
        return 0
    fi

    where=""
    for d in $MS_COOKIE_DOMAINS; do
        [ -n "$where" ] && where="$where OR "
        where="${where}host_key LIKE '%${d}'"
    done
    where="$where OR top_frame_site_key LIKE '%microsoft%'"

    if [ "$SCOPE_DRY" = "1" ]; then
        cnt=$(sqlite3 "$db" "SELECT COUNT(*) FROM cookies WHERE $where;" 2>/dev/null)
        log DRY "$label - WOULD delete ${cnt:-?} Microsoft cookie(s), leaving all other sites signed in."
        return 0
    fi

    # Back the DB up before surgery, and verify integrity after.
    bd=$(backup_dir_for "$home" "${4:-root}")
    [ -n "$bd" ] && cp -p "$db" "$bd/$(basename "$db").$(basename "$(dirname "$db")").bak" 2>/dev/null

    before=$(sqlite3 "$db" "SELECT COUNT(*) FROM cookies;" 2>/dev/null)
    if sqlite3 "$db" "DELETE FROM cookies WHERE $where;" 2>/dev/null; then
        ok=$(sqlite3 "$db" "PRAGMA integrity_check;" 2>/dev/null | head -1)
        after=$(sqlite3 "$db" "SELECT COUNT(*) FROM cookies;" 2>/dev/null)
        if [ "$ok" = "ok" ]; then
            log OK "$label - removed $(( ${before:-0} - ${after:-0} )) Microsoft cookie(s); other sites untouched."
            ITEMS_REMOVED=$((ITEMS_REMOVED + 1))
        else
            log WARN "$label - cookie DB failed integrity check after edit; restore from $bd if needed."
        fi
    else
        log WARN "$label - could not edit cookie database (browser may still be running)."
    fi
    return 0
}

chromium_ms_sitestorage() {
    # Per-origin IndexedDB directories are named after the origin, so these CAN be targeted.
    pdir="$1"; label="$2"; home="$3"
    idb="$pdir/IndexedDB"
    if [ -d "$idb" ]; then
        for d in "$idb"/https_*microsoft*  "$idb"/https_*office*  "$idb"/https_*sharepoint*  "$idb"/https_*live.com*; do
            [ -e "$d" ] || continue
            remove_path "$d" "$home" "$label - site storage $(basename "$d")"
        done
    fi
    # Service Worker stores are opaque caches; sites re-register them. Safe to clear whole.
    for d in "Service Worker/CacheStorage" "Service Worker/ScriptCache"; do
        [ -d "$pdir/$d" ] && clear_folder "$pdir/$d" "$home" "$label - $d"
    done
    return 0
}

clean_chromium_profile_full() {
    pdir="$1"; cdir="$2"; home="$3"; label="$4"
    for f in "Network/Cookies" "Network/Cookies-journal" "Cookies" "Cookies-journal" \
             "Current Session" "Current Tabs" "Last Session" "Last Tabs"; do
        [ -f "$pdir/$f" ] && remove_path "$pdir/$f" "$home" "$label - $f"
    done
    for d in "Sessions" "Session Storage" "GPUCache" "Service Worker/CacheStorage" \
             "Service Worker/ScriptCache" "Local Storage/leveldb" "IndexedDB"; do
        [ -d "$pdir/$d" ] && clear_folder "$pdir/$d" "$home" "$label - $d"
    done
    for d in "Cache" "Code Cache" "GPUCache"; do
        [ -d "$cdir/$d" ] && clear_folder "$cdir/$d" "$home" "$label - cache/$d"
    done
    log INFO "$label - bookmarks, saved passwords, autofill and extensions preserved."
    return 0
}

clean_chromium_browser() {
    home="$1"; as_rel="$2"; ca_rel="$3"; name="$4"; owner="$5"
    base="$home/Library/Application Support/$as_rel"
    cbase="$home/Library/Caches/$ca_rel"
    [ -d "$base" ] || { log SKIP "$name not installed for this user."; return 0; }

    for pdir in "$base/Default" "$base"/Profile\ *; do
        [ -d "$pdir" ] || continue
        pname=$(basename "$pdir")
        label="$name / $pname"
        if [ "$BROWSER_MODE" = "microsoft" ]; then
            db="$pdir/Network/Cookies"; [ -f "$db" ] || db="$pdir/Cookies"
            chromium_ms_cookies "$db" "$label" "$home" "$owner"
            chromium_ms_sitestorage "$pdir" "$label" "$home"
        else
            clean_chromium_profile_full "$pdir" "$cbase/$pname" "$home" "$label"
        fi
    done
    return 0
}

clean_safari() {
    home="$1"
    container="$home/Library/Containers/com.apple.Safari/Data/Library"
    if [ ! -d "$home/Library/Containers/com.apple.Safari" ]; then
        log SKIP "Safari container not present for this user."
        return 0
    fi
    if ! tcc_check "$container"; then
        TCC_DENIED=1
        log WARN "Safari data is protected by macOS privacy (TCC) and this process lacks Full Disk Access."
        log WARN "Grant FDA to the RMM agent via an MDM PPPC profile, then re-run. Safari NOT cleaned."
        return 0
    fi

    if [ "$BROWSER_MODE" = "microsoft" ]; then
        # Safari's cookie store is a single opaque binary file - it cannot be filtered per
        # site from the CLI. Be honest rather than pretend.
        log WARN "Safari cannot be cleaned per-domain (single binary cookie store)."
        log WARN "Safari left untouched in --browsers microsoft mode. Use 'all', or in Safari:"
        log WARN "  Settings > Privacy > Manage Website Data > search 'microsoft' > Remove."
        return 0
    fi

    remove_path "$container/Cookies/Cookies.binarycookies" "$home" "Safari cookies"
    remove_path "$home/Library/Cookies/Cookies.binarycookies" "$home" "Safari cookies (legacy path)"
    # WebKit/WebsiteData is where Safari keeps LocalStorage/IndexedDB/ServiceWorkers, i.e.
    # the Microsoft web sign-in tokens. Bookmarks and History live elsewhere.
    clear_folder "$container/WebKit" "$home" "Safari website data (site tokens)"
    clear_folder "$container/Caches" "$home" "Safari container caches"
    clear_folder "$home/Library/Caches/com.apple.Safari" "$home" "Safari cache"
    remove_path "$home/Library/HTTPStorages/com.apple.Safari" "$home" "Safari HTTP storage"
    remove_path "$container/Safari/LastSession.plist" "$home" "Safari last session"
    log INFO "Safari - bookmarks, history and keychain passwords preserved."
    return 0
}

clean_browsers() {
    home="$1"; uname_="$2"
    if [ "$BROWSER_MODE" = "none" ]; then
        log SKIP "Browser cleanup skipped (--browsers none)."
        return 0
    fi
    log STEP "--- Browsers (mode: $BROWSER_MODE): $uname_ ---"

    # A running Chromium keeps cookies in memory and rewrites the DB on exit, silently
    # undoing our work. Never edit a live profile.
    if [ "$SCOPE_DRY" != "1" ] && browsers_running; then
        log WARN "A browser is still running - cookie changes would be reverted when it exits."
        log WARN "Skipping browser cleanup. Close all browsers (or use --force) and re-run."
        DEFERRED=1
        return 0
    fi

    clean_chromium_browser "$home" "Google/Chrome"  "Google/Chrome"  "Google Chrome"  "$uname_"
    clean_chromium_browser "$home" "Microsoft Edge" "Microsoft Edge" "Microsoft Edge" "$uname_"
    clean_safari "$home"

    if [ "$BROWSER_MODE" = "microsoft" ]; then
        log WARN "Reminder: in 'microsoft' mode, browser Local Storage is left in place because"
        log WARN "it cannot be filtered per site. If Teams/Outlook web are still signed in,"
        log WARN "re-run with --browsers all for that user."
    fi
    return 0
}

# =============================================================================================
#  KEYCHAIN - the actual credential revocation
#  Runs only for the signed-in console user: the login keychain is per-user, session-bound
#  and must be unlocked. Every call is watchdogged, and none of them decrypt a secret
#  (no -w / -g), which is what would otherwise raise a blocking password dialog.
# =============================================================================================
kc_delete() {
    # kc_delete <user> <uid> <keychain> <kind: generic|internet> <selector: -l|-s|-a> <value>
    ku="$1"; kuid="$2"; kc="$3"; kind="$4"; sel="$5"; val="$6"

    # Belt and braces: never let a browser Safe Storage key be deleted.
    case "$val" in
        *"Safe Storage"*) log SKIP "Keychain: refusing protected item '$val'."; return 0 ;;
    esac

    cmd="delete-generic-password"
    [ "$kind" = "internet" ] && cmd="delete-internet-password"
    find_cmd="find-generic-password"
    [ "$kind" = "internet" ] && find_cmd="find-internet-password"

    if [ "$SCOPE_DRY" = "1" ]; then
        # Attribute-only lookup; does not decrypt, so it cannot prompt.
        if run_as_user_capped "$ku" "$kuid" 20 security "$find_cmd" "$sel" "$val" "$kc"; then
            log DRY "WOULD delete keychain item(s): $sel '$val'"
        fi
        return 0
    fi

    n=0
    while [ "$n" -lt 20 ]; do
        run_as_user_capped "$ku" "$kuid" 20 security "$cmd" "$sel" "$val" "$kc"
        rc=$?
        if [ "$rc" = "124" ]; then
            log WARN "Keychain: timed out on '$val' - the login keychain is probably locked."
            log WARN "  Have the user log in and unlock their keychain, then re-run."
            DEFERRED=1
            return 1
        fi
        [ "$rc" != "0" ] && break
        n=$((n + 1))
    done
    if [ "$n" -gt 0 ]; then
        ITEMS_REMOVED=$((ITEMS_REMOVED + n))
        log OK "Keychain: deleted $n item(s) matching $sel '$val'"
    fi
    return 0
}

clean_keychain() {
    uname_="$1"; uid_="$2"; home="$3"
    if [ "$SKIP_KEYCHAIN" = "1" ]; then
        log SKIP "Keychain cleanup skipped (--skip-keychain)."
        return 0
    fi
    log STEP "--- Credential revocation (login keychain): $uname_ ---"

    kc="$home/Library/Keychains/login.keychain-db"
    if [ ! -f "$kc" ]; then
        log WARN "login.keychain-db not found for $uname_ - keychain steps skipped."
        return 0
    fi

    # If the login keychain is not in the search list, every delete silently no-ops.
    run_as_user_capped "$uname_" "$uid_" 15 security list-keychains -s "$kc"

    # Microsoft-documented Outlook/Office credential items.
    for l in \
        "Exchange" \
        "Microsoft Office Identities Cache 2" \
        "Microsoft Office Identities Cache 3" \
        "Microsoft Office Identities Settings 2" \
        "Microsoft Office Identities Settings 3" \
        "Microsoft Office Ticket Cache" \
        "Microsoft Office Ticket Cache 2" \
        "Microsoft Office Credentials" \
        "com.microsoft.adalcache" \
        "com.microsoft.OutlookCore.Secret" \
        "com.helpshift.data_com.microsoft.Outlook" \
        "MicrosoftOfficeRMSCredential" \
        "MSProtection.framework.service" \
        "com.microsoft.office.rmscache" \
        "Microsoft Teams Identities Cache" \
        "teamsIv" "teamsKey" \
        "OneDrive Cached Credential" \
        "OneDrive Standalone Cached Credential" \
        "OneDrive Standalone Cached Credential Business - Business1" \
        ; do
        kc_delete "$uname_" "$uid_" "$kc" generic -l "$l" || return 0
    done

    for s in "OneAuthAccount" "com.microsoft.onedrive.cookies"; do
        kc_delete "$uname_" "$uid_" "$kc" generic -s "$s" || return 0
    done

    for s in "msoCredentialSchemeADAL" "msoCredentialSchemeLiveId" "msoCredentialSchemeUnknown"; do
        kc_delete "$uname_" "$uid_" "$kc" internet -s "$s" || return 0
    done

    # OneAuth/MSAL broker tokens live in the data-protection keychain, which the `security`
    # tool cannot reach. This is the account list Office and Teams show in their pickers.
    kc2=$(find "$home/Library/Keychains" -maxdepth 2 -name "keychain-2.db" 2>/dev/null | head -1)
    if [ -n "$kc2" ] && [ -f "$kc2" ] && command -v sqlite3 >/dev/null 2>&1; then
        if [ "$SCOPE_DRY" = "1" ]; then
            log DRY "WOULD purge the OneAuth account/token group from the data-protection keychain"
        elif sqlite3 "$kc2" "DELETE FROM genp WHERE agrp='UBF8T346G9.com.microsoft.identity.universalstorage';" 2>/dev/null; then
            log OK "Purged OneAuth account/token store - account pickers will be empty."
        else
            log INFO "OneAuth data-protection store not writable here; the staged ResetOneAuthCreds"
            log INFO "  flag will clear it at next app launch instead."
        fi
    fi

    log OK "Credential revocation pass complete. Non-Microsoft keychain items untouched."
    return 0
}

clean_work_account() {
    uname_="$1"; uid_="$2"; home="$3"
    if [ "$SKIP_WORKACCOUNT" = "1" ] || [ "$SKIP_KEYCHAIN" = "1" ]; then
        log SKIP "Work account removal skipped."
        return 0
    fi
    log STEP "--- Work account / Entra registration: $uname_ ---"
    kc="$home/Library/Keychains/login.keychain-db"
    [ -f "$kc" ] || return 0

    for a in \
        "com.microsoft.workplacejoin.thumbprint" \
        "com.microsoft.workplacejoin.registeredUserPrincipalName" \
        "com.microsoft.workplacejoin.deviceOSVersion" \
        "com.microsoft.workplacejoin.devicePatchAttemptTimestamp" \
        "com.microsoft.workplacejoin.tenantId" \
        "com.microsoft.workplacejoin.tenantDisplayName" \
        "com.microsoft.workplacejoin.cloudEnvironment" \
        "com.microsoft.workplacejoin.deviceName" \
        ; do
        kc_delete "$uname_" "$uid_" "$kc" generic -a "$a" || return 0
    done
    for l in "com.microsoft.CompanyPortal" "com.microsoft.CompanyPortalMac" \
             "com.microsoft.CompanyPortal.HockeySDK" "enterpriseregistration.windows.net" \
             "https://enterpriseregistration.windows.net" "https://device.login.microsoftonline.com"; do
        kc_delete "$uname_" "$uid_" "$kc" generic -l "$l" || return 0
    done

    # The Entra device certificate + key (issuer MS-ORGANIZATION-ACCESS, CN = device ID).
    if [ "$SCOPE_DRY" = "1" ]; then
        log DRY "WOULD remove the MS-ORGANIZATION-ACCESS device identity if present"
        return 0
    fi
    devid=$(launchctl asuser "$uid_" sudo -u "$uname_" security find-certificate -a -Z "$kc" 2>/dev/null |
            grep -B 9 'MS-ORGANIZATION-ACCESS' | awk -F'"' '/"alis"<blob>=/ {print $4}' | head -1)
    if [ -n "$devid" ]; then
        if run_as_user_capped "$uname_" "$uid_" 30 security delete-identity -c "$devid" "$kc"; then
            log OK "Removed Entra device identity (cert + key): $devid"
            ITEMS_REMOVED=$((ITEMS_REMOVED + 1))
        else
            log WARN "Found Entra device identity '$devid' but could not remove it."
        fi
    else
        log SKIP "No MS-ORGANIZATION-ACCESS device certificate found."
    fi
    log INFO "Reminder: delete the stale device object in the OLD tenant (Entra > Devices)."
    return 0
}

# =============================================================================================
#  MDM (report only)
# =============================================================================================
report_mdm_state() {
    log STEP "--- MDM enrollment state (report only - never modified) ---"
    if ! command -v profiles >/dev/null 2>&1; then
        log INFO "profiles tool unavailable - MDM state unknown."
        return 0
    fi
    st=$(profiles status -type enrollment 2>/dev/null)
    if [ -n "$st" ]; then
        echo "$st" | while IFS= read -r l; do log INFO "  $l"; done
        if echo "$st" | grep -qi "MDM enrollment: Yes"; then
            log WARN "Device is MDM-enrolled. This script never unenrolls it."
            log WARN "While it stays enrolled to the OLD tenant, the SSO extension can re-register"
            log WARN "the work account. Retire the device from the MDM console to finish the move."
        fi
    else
        log INFO "No enrollment reported (not MDM-enrolled)."
    fi
    return 0
}

# =============================================================================================
#  SUMMARY
# =============================================================================================
write_summary() {
    dur=$(( $(date +%s) - START_EPOCH ))
    log STEP "================================================================="
    log STEP "                        SUMMARY"
    log STEP "================================================================="
    log INFO "Computer            : $HOSTNAME_SHORT"
    log INFO "Script version      : $SCRIPT_VERSION"
    log INFO "Mode                : $([ "$SCOPE_DRY" = "1" ] && echo 'DRY RUN - nothing changed' || echo 'LIVE')"
    log INFO "Browser mode        : $BROWSER_MODE"
    log INFO "Users processed     : $PROCESSED_USERS"
    log INFO "Items removed       : $ITEMS_REMOVED"
    log INFO "Space reclaimed     : $(fmt_bytes "$BYTES_FREED")"
    log INFO "Warnings            : $WARN_COUNT"
    log INFO "Errors              : $ERROR_COUNT"
    log INFO "Outlook mail data   : NOT TOUCHED (protected by deny-list)"
    log INFO "Deferred            : $([ "$DEFERRED" = "1" ] && echo 'YES - re-run needed' || echo 'No')"
    log INFO "Restart recommended : $([ "$RESTART_RECOMMENDED" = "1" ] && echo 'YES - items were locked' || echo 'No')"
    log INFO "Duration            : ${dur}s"
    log INFO "Log file            : ${LOG_FILE:-'(console only)'}"
    log STEP "================================================================="
    log INFO "USER ACTION REQUIRED IN OUTLOOK:"
    log INFO "  Tools > Accounts > select the OLD account > Manage > 'Remove Account'."
    log INFO "  Never choose 'Reset Account' - it deletes 'On My Computer' mail."
    log STEP "================================================================="

    if [ -n "$RECEIPT_FILE" ]; then
        {
            printf '{\n'
            printf '  "version": "%s",\n'          "$SCRIPT_VERSION"
            printf '  "computer": "%s",\n'         "$HOSTNAME_SHORT"
            printf '  "dryRun": %s,\n'             "$([ "$SCOPE_DRY" = "1" ] && echo true || echo false)"
            printf '  "browserMode": "%s",\n'      "$BROWSER_MODE"
            printf '  "usersProcessed": %s,\n'     "$PROCESSED_USERS"
            printf '  "itemsRemoved": %s,\n'       "$ITEMS_REMOVED"
            printf '  "bytesFreed": %s,\n'         "$BYTES_FREED"
            printf '  "warnings": %s,\n'           "$WARN_COUNT"
            printf '  "errors": %s,\n'             "$ERROR_COUNT"
            printf '  "outlookMailTouched": false,\n'
            printf '  "deferred": %s,\n'           "$([ "$DEFERRED" = "1" ] && echo true || echo false)"
            printf '  "tccDenied": %s,\n'          "$([ "$TCC_DENIED" = "1" ] && echo true || echo false)"
            printf '  "restartRecommended": %s,\n' "$([ "$RESTART_RECOMMENDED" = "1" ] && echo true || echo false)"
            printf '  "completedUtc": "%s"\n'      "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            printf '}\n'
        } > "$RECEIPT_FILE" 2>/dev/null && log INFO "Receipt: $RECEIPT_FILE"
    fi
    return 0
}

cleanup_lock() {
    [ "$LOCK_HELD" = "1" ] && rm -rf "$LOCK_DIR" 2>/dev/null
    return 0
}

# =============================================================================================
#  MAIN
# =============================================================================================
main() {
    # stdin is the script itself when piped from curl. Detach it so no child can eat the
    # remaining script bytes or hang waiting on input.
    exec </dev/null

    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run)             SCOPE_DRY=1; shift ;;
            --force)               FORCE=1; shift ;;
            --grace)               GRACE="${2:-45}"; shift 2 ;;
            --console-user-only)   CONSOLE_ONLY=1; shift ;;
            --browsers)            BROWSER_MODE="${2:-all}"; shift 2 ;;
            --skip-browsers)       BROWSER_MODE="none"; shift ;;
            --skip-onedrive)       SKIP_ONEDRIVE=1; shift ;;
            --force-onedrive)      FORCE_ONEDRIVE=1; shift ;;
            --skip-keychain)       SKIP_KEYCHAIN=1; shift ;;
            --skip-workaccount)    SKIP_WORKACCOUNT=1; shift ;;
            --skip-teams)          SKIP_TEAMS=1; shift ;;
            --reset-outlook-prefs) RESET_OUTLOOK_PREFS=1; shift ;;
            --log-dir)             LOG_DIR="${2:-$LOG_DIR}"; shift 2 ;;
            *) echo "Unknown flag: $1" >&2; shift ;;
        esac
    done

    case "$BROWSER_MODE" in all|microsoft|none) : ;; *)
        echo "Invalid --browsers '$BROWSER_MODE' (all|microsoft|none)" >&2; return 64 ;;
    esac

    init_logging
    trap cleanup_lock EXIT INT TERM

    log STEP "================================================================="
    log STEP " Post-Migration Credential Cleanup for macOS  v$SCRIPT_VERSION"
    log STEP " Microsoft 365 tenant-to-tenant - credentials and tokens only"
    log STEP " OUTLOOK MAIL DATA IS PROTECTED AND WILL NOT BE TOUCHED"
    log STEP "================================================================="

    if [ "$(id -u)" != "0" ]; then
        log ERROR "Must run as root. Use:  curl -fsSL <URL> | sudo bash -s --"
        log ERROR "(note: 'sudo' goes on bash, not on curl)"
        return 64
    fi

    # Single-instance lock (macOS has no flock; mkdir is the atomic primitive).
    if ! mkdir "$LOCK_DIR" 2>/dev/null; then
        if [ -n "$(find "$LOCK_DIR" -maxdepth 0 -mmin +30 2>/dev/null)" ]; then
            rm -rf "$LOCK_DIR" 2>/dev/null
            mkdir "$LOCK_DIR" 2>/dev/null || { log ERROR "Could not acquire lock."; return 75; }
        else
            log WARN "Another run is already in progress. Exiting; the RMM should retry later."
            return 75
        fi
    fi
    LOCK_HELD=1

    log INFO "macOS version    : $(sw_vers -productVersion 2>/dev/null || echo unknown)"
    log INFO "Browser mode     : $BROWSER_MODE"
    [ "$SCOPE_DRY" = "1" ] && log DRY "DRY RUN - no changes will be made."

    [ "$SCOPE_DRY" != "1" ] && command -v caffeinate >/dev/null 2>&1 && caffeinate -dimsu -w $$ &

    get_console_user
    if [ -n "$CONSOLE_USER" ]; then
        log INFO "Console user     : $CONSOLE_USER (uid $CONSOLE_UID)"
    else
        log WARN "No user is signed in at the GUI."
        log WARN "Credential revocation needs an unlocked login keychain, so it cannot run now."
        log WARN "File-level caches will still be cleared; re-run after the user signs in."
    fi

    report_mdm_state

    if ! quit_apps; then
        log WARN "Applications were not closed - stopping before making any changes."
        write_summary
        return 75
    fi

    if [ "$CONSOLE_ONLY" = "1" ]; then
        users="$CONSOLE_USER"
    else
        users=$(list_local_users)
    fi
    users=$(echo "$users" | awk 'NF' | sort -u)
    if [ -z "$users" ]; then
        log ERROR "No eligible user account found."
        write_summary
        return 75
    fi
    log INFO "Target users     : $(echo "$users" | tr '\n' ' ')"

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
        log STEP " USER   : $U"
        log STEP " Home   : $HOMEDIR"
        log STEP " Active : $([ "$U" = "$CONSOLE_USER" ] && echo yes || echo no)"
        log STEP "#################################################################"

        preflight_report          "$HOMEDIR" "$U"
        clean_outlook_credentials "$HOMEDIR" "$U"
        clean_office              "$HOMEDIR" "$U"
        clean_teams               "$HOMEDIR" "$U"
        clean_onedrive            "$HOMEDIR" "$U"
        clean_browsers            "$HOMEDIR" "$U"
        clean_company_portal      "$HOMEDIR" "$U"
        check_outlook_store_clean "$HOMEDIR"

        if [ -n "$CONSOLE_USER" ] && [ "$U" = "$CONSOLE_USER" ] && [ -n "$UID_N" ]; then
            clean_office_prefs_userctx "$U" "$UID_N"
            clean_keychain     "$U" "$UID_N" "$HOMEDIR"
            clean_work_account "$U" "$UID_N" "$HOMEDIR"
        else
            log INFO "$U is not the signed-in user - keychain steps deferred to a later run."
        fi

        PROCESSED_USERS=$((PROCESSED_USERS + 1))
    done <<EOF_USERS
$users
EOF_USERS

    [ "$RESTART_RECOMMENDED" = "1" ] && log WARN "RESTART RECOMMENDED: some items were locked by running processes."

    write_summary

    if   [ "$TCC_DENIED" = "1" ]   && [ "$ERROR_COUNT" -eq 0 ]; then return 77
    elif [ "$ERROR_COUNT" -gt 0 ]; then return 2
    elif [ "$DEFERRED" = "1" ];    then return 75
    elif [ "$WARN_COUNT" -gt 0 ];  then return 1
    fi
    return 0
}

main "$@"; exit $?
} # ===== END TRUNCATION GUARD =====
