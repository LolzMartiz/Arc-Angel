#!/bin/bash
# =============================================================================================
#  clearCacheMac.sh                                                                     v3.0.0
#  Microsoft 365 tenant-to-tenant post-migration cleanup for macOS.
#
#  macOS counterpart of Invoke-PostMigrationCleanup.ps1 v4.1.1.
#
# ---------------------------------------------------------------------------------------------
#  WHAT CHANGED FROM v2.0.0, AND WHY IT MATTERED
#
#  v2 was not tenant-scoped. Every removal was wholesale, so on a Mac that already had the
#  NEW tenant signed in it removed that account too:
#
#    OneAuth group container      deleted entire     -> every account, both tenants
#    Office Identity store        deleted entire     -> every identity
#    keychain label allow-list    deleted by label   -> new tenant's tokens went with them
#    keychain-2.db genp DELETE    whole access group -> the entire account picker
#    OneDrive settings            cleared all        -> every business link
#    Outlook profile              moved by default   -> the new mailbox too
#    Workplace Join / device cert removed blind      -> even when it belonged to the new tenant
#
#  v3 walks each of those stores item by item and applies a UPN suffix gate to every one.
#  What genuinely cannot be scoped to a single tenant is split out, kept out of every preset,
#  and refuses to run without --i-accept-all-account-impact.
#
#  v2 also deleted the keychain item labelled "Exchange". That label is used by Apple Mail and
#  Internet Accounts, not only by Microsoft, so a personal or third-party Exchange account
#  could lose its stored credential. v3 never deletes by bare label; it reads each item's
#  account and service attributes and matches the target domain.
#
#  NEW IN v3: the Microsoft Enterprise SSO extension (app-sso). On a Mac this holds the shared
#  broker token - the closest thing to a Windows PRT - and hands it to every app that asks.
#  v2 did not touch it at all, which is the most likely reason an account kept coming back on
#  Macs that looked clean everywhere else.
#
# ---------------------------------------------------------------------------------------------
#  NEVER TOUCHED, IN ANY MODULE, EVER
#    *.olm *.pst *.mbox *.eml *.emlx      mail archives - rescued out of any folder being removed
#    the Outlook profile database          unless --modules OutlookProfileAll, and even then it
#                                          is MOVED to a visible backup folder, never deleted
#    Documents Desktop Downloads Pictures Movies Music Public
#    ~/Library/CloudStorage, ~/OneDrive*, ~/Library/Mobile Documents     synced files
#    browser bookmarks, saved passwords, autofill, extensions, history
#    Chrome / Edge "Safe Storage" keychain keys   deleting these destroys saved passwords
#    MDM enrolment                          detected and reported, never removed
#    any account whose UPN does not end in @<target domain>
#
# ---------------------------------------------------------------------------------------------
#  USAGE
#    curl -fsSL <RAW_URL> | bash -s -- --list-modules
#    curl -fsSL <RAW_URL> | bash -s -- --modules Delta --dry-run
#    curl -fsSL <RAW_URL> | bash -s -- --modules Delta
#    curl -fsSL <RAW_URL> | bash -s -- --modules DeltaKeychain,AppCache
#
#  Run as root (RMM/agent context or sudo). $HOME under root is /var/root, so this script
#  never reads $HOME - real accounts come from Directory Services, and session-bound work
#  runs inside the console user's own session via launchctl asuser.
#
#  EXIT CODES
#    0 clean   1 completed with warnings   2 refused or fatal   3 no eligible user
#    5 a target-domain item survived the run
# =============================================================================================

set -u
SCRIPT_VERSION="3.0.0"

# macOS ships bash 3.2. No associative arrays, no ${var,,}, no mapfile. Keep it portable.

# ------------------------------------- defaults ----------------------------------------------
TARGET_DOMAINS="delta.mainettigroup.onmicrosoft.com"
OLD_TENANT_ID="905cd5ac-a071-4697-a446-c9077a81e24b"
NEW_TENANT_ID="152848e0-5270-46fc-b573-8719c78aa236"
MODULES_ARG="Delta"
DRY_RUN=0
FORCE=0
GRACE=15
CONSOLE_ONLY=0
ACCEPT_ALL_ACCOUNT=0
LIST_MODULES=0
LOG_DIR="/Library/Logs/PostMigrationCleanup"

while [ $# -gt 0 ]; do
    case "$1" in
        --modules)                   MODULES_ARG="${2-}"; shift 2 ;;
        --target-domain)             TARGET_DOMAINS="${2-}"; shift 2 ;;
        --old-tenant-id)             OLD_TENANT_ID="${2:-$OLD_TENANT_ID}"; shift 2 ;;
        --new-tenant-id)             NEW_TENANT_ID="${2:-$NEW_TENANT_ID}"; shift 2 ;;
        --dry-run)                   DRY_RUN=1; shift ;;
        --force)                     FORCE=1; shift ;;
        --grace)                     GRACE="${2:-15}"; shift 2 ;;
        --console-user-only)         CONSOLE_ONLY=1; shift ;;
        --i-accept-all-account-impact) ACCEPT_ALL_ACCOUNT=1; shift ;;
        --list-modules)              LIST_MODULES=1; shift ;;
        --log-dir)                   LOG_DIR="${2:-$LOG_DIR}"; shift 2 ;;
        -h|--help)                   LIST_MODULES=1; shift ;;
        *) echo "Unknown flag: $1" >&2; shift ;;
    esac
done

# Strip quotes an RMM may pass through verbatim, and turn separators into spaces.
TARGET_DOMAINS=$(printf '%s' "$TARGET_DOMAINS" | tr ',;' '  ' | tr -d "\"'")
MODULES_ARG=$(printf '%s'    "$MODULES_ARG"    | tr ',;' '  ' | tr -d "\"'")
OLD_TENANT_ID=$(printf '%s'  "$OLD_TENANT_ID"  | tr -d "\"'")
NEW_TENANT_ID=$(printf '%s'  "$NEW_TENANT_ID"  | tr -d "\"'")

if [ -z "$(printf '%s' "$TARGET_DOMAINS" | tr -d ' ')" ]; then
    echo "No target domain supplied. Refusing to run." >&2; exit 2
fi
if [ -z "$(printf '%s' "$MODULES_ARG" | tr -d ' ')" ]; then
    echo "No modules supplied. Use --list-modules to see them." >&2; exit 2
fi

# ============================================================================================
#  MODULE REGISTRY
#    DeltaOnly    touches only items whose UPN ends in @<target domain>
#    CacheOnly    deletes caches, no account is removed, nothing signs out
#    SignsOut     no account is removed, but every account must authenticate again
#    AllAccounts  affects accounts other than the target - gated
# ============================================================================================
MODULE_NAMES="DeltaKeychain DeltaTokens DeltaOffice DeltaOneDrive DeltaBrowser DeltaSSO DeltaWorkAccount AppCache OutlookCache TokenStoreAll KeychainAll BrowserAll OneDriveAll OutlookProfileAll CompanyPortalAll"

module_scope() {
    case "$1" in
        DeltaKeychain|DeltaTokens|DeltaOffice|DeltaOneDrive|DeltaBrowser|DeltaSSO|DeltaWorkAccount) echo DeltaOnly ;;
        AppCache|OutlookCache)                                                                       echo CacheOnly ;;
        TokenStoreAll|KeychainAll|BrowserAll)                                                        echo SignsOut ;;
        OneDriveAll|OutlookProfileAll|CompanyPortalAll)                                              echo AllAccounts ;;
        *) echo Unknown ;;
    esac
}
module_desc() {
    case "$1" in
      DeltaKeychain)     echo "Login-keychain items whose account or service names the old tenant. Every other item kept." ;;
      DeltaTokens)       echo "OneAuth / MSAL account files naming the old tenant. Other tenants' entries stay." ;;
      DeltaOffice)       echo "Office identity and licence entries for the old tenant only." ;;
      DeltaOneDrive)     echo "Unlink only the old-tenant OneDrive business account. Synced files never deleted." ;;
      DeltaBrowser)      echo "Chrome/Edge profile signed in with the old tenant. Mixed profiles reported, not touched." ;;
      DeltaSSO)          echo "Microsoft Enterprise SSO extension token for the old tenant - the Mac's shared broker token." ;;
      DeltaWorkAccount)  echo "Workplace Join records and the device certificate, ONLY when they prove to be the old tenant." ;;
      AppCache)          echo "Office / Teams / Company Portal scratch caches. Nothing signs out." ;;
      OutlookCache)      echo "Outlook container caches only. Never the profile, never mail." ;;
      TokenStoreAll)     echo "ALL ACCOUNTS: purge the whole OneAuth store. Everyone signs in again." ;;
      KeychainAll)       echo "ALL ACCOUNTS: delete every Microsoft token item in the login keychain." ;;
      BrowserAll)        echo "ALL ACCOUNTS: cookies and site storage for every browser profile." ;;
      OneDriveAll)       echo "ALL ACCOUNTS: unlink every OneDrive business account." ;;
      OutlookProfileAll) echo "ALL ACCOUNTS: move the Outlook profile to a visible backup folder. Reversible, never deleted." ;;
      CompanyPortalAll)  echo "ALL ACCOUNTS: remove Company Portal data and the Entra entity-certificate keychain." ;;
      *) echo "" ;;
    esac
}
PRESET_DELTA="DeltaKeychain DeltaTokens DeltaOffice DeltaOneDrive DeltaSSO DeltaWorkAccount"
PRESET_SAFE="$PRESET_DELTA DeltaBrowser AppCache OutlookCache"
PRESET_FULL="$PRESET_SAFE TokenStoreAll BrowserAll"

if [ "$LIST_MODULES" = "1" ]; then
    printf '\n  clearCacheMac.sh  v%s   modules\n' "$SCRIPT_VERSION"
    printf '  %s\n' "------------------------------------------------------------------------------------------------"
    for m in $MODULE_NAMES; do
        printf '  %-18s %-12s %s\n' "$m" "$(module_scope "$m")" "$(module_desc "$m")"
    done
    printf '  %s\n' "------------------------------------------------------------------------------------------------"
    printf '  preset Delta  = %s\n                    everything tied to the old tenant, and nothing else - the fleet default\n' "$PRESET_DELTA"
    printf '  preset Safe   = %s\n                    Delta, plus its browser profile and caches that lose nothing\n' "$PRESET_SAFE"
    printf '  preset Full   = %s\n                    Safe, plus the shared token stores - every account signs in again\n' "$PRESET_FULL"
    printf '\n  AllAccounts modules are in no preset and refuse to run without --i-accept-all-account-impact.\n\n'
    exit 0
fi

# --------------------------------- resolve --modules -----------------------------------------
SELECTED=""
UNKNOWN=""
sel_add() {
    local n="$1" s
    for s in $SELECTED; do [ "$s" = "$n" ] && return 0; done
    SELECTED="$SELECTED $n"
}
for tok in $MODULES_ARG; do
    case "$(printf '%s' "$tok" | tr '[:upper:]' '[:lower:]')" in
        delta) for n in $PRESET_DELTA; do sel_add "$n"; done; continue ;;
        safe)  for n in $PRESET_SAFE;  do sel_add "$n"; done; continue ;;
        full)  for n in $PRESET_FULL;  do sel_add "$n"; done; continue ;;
        all)   for n in $PRESET_FULL;  do sel_add "$n"; done
               echo 'NOTE: "All" resolves to the Full preset. All-account modules are never included' >&2
               echo '      by a preset - name them explicitly if you really want them.' >&2
               continue ;;
    esac
    hit=0
    for n in $MODULE_NAMES; do
        if [ "$(printf '%s' "$tok" | tr '[:upper:]' '[:lower:]')" = "$(printf '%s' "$n" | tr '[:upper:]' '[:lower:]')" ]; then
            sel_add "$n"; hit=1; break
        fi
    done
    [ "$hit" = "0" ] && UNKNOWN="$UNKNOWN $tok"
done

if [ -n "$(printf '%s' "$UNKNOWN" | tr -d ' ')" ]; then
    echo "Unknown module(s):$UNKNOWN" >&2
    echo "Valid: $MODULE_NAMES" >&2
    echo "Presets: Delta, Safe, Full" >&2
    exit 2
fi
if [ -z "$(printf '%s' "$SELECTED" | tr -d ' ')" ]; then
    echo "No modules selected. Nothing to do." >&2; exit 0
fi

GATED=""
for n in $SELECTED; do
    [ "$(module_scope "$n")" = "AllAccounts" ] && GATED="$GATED $n"
done
if [ -n "$(printf '%s' "$GATED" | tr -d ' ')" ] && [ "$ACCEPT_ALL_ACCOUNT" != "1" ]; then
    echo ""
    echo "REFUSING TO RUN." >&2
    echo "These modules affect work accounts other than the old tenant:" >&2
    for n in $GATED; do echo "   $n  -  $(module_desc "$n")" >&2; done
    echo "" >&2
    echo "Re-run with --i-accept-all-account-impact if that is what you intend, or drop them." >&2
    echo "The delta-only work needs none of them: --modules Delta" >&2
    exit 2
fi

has_module() {
    local n="$1" s
    for s in $SELECTED; do [ "$s" = "$n" ] && return 0; done
    return 1
}

# ============================================================================================
#  STATE AND LOGGING
# ============================================================================================
WARN_COUNT=0; ERROR_COUNT=0; ITEMS_REMOVED=0; ITEMS_KEPT=0; BYTES_FREED=0
RESTART_RECOMMENDED=0; PROCESSED_USERS=0; TARGET_STILL_PRESENT=0
START_EPOCH=$(date +%s)
HOSTNAME_SHORT=$(hostname -s 2>/dev/null || echo "unknown-mac")
LOG_FILE=""; RECEIPT_FILE=""; ACTIONS_FILE=""
CONSOLE_USER=""; CONSOLE_UID=""
STAMP=$(date +%Y%m%d-%H%M%S)

init_logging() {
    mkdir -p "$LOG_DIR" 2>/dev/null || { LOG_DIR="/tmp/PostMigrationCleanup"; mkdir -p "$LOG_DIR" 2>/dev/null; }
    LOG_FILE="$LOG_DIR/Cleanup-$HOSTNAME_SHORT-$STAMP.log"
    RECEIPT_FILE="$LOG_DIR/receipt-$HOSTNAME_SHORT-$STAMP.json"
    ACTIONS_FILE="$LOG_DIR/actions-$HOSTNAME_SHORT-$STAMP.tsv"
    : > "$LOG_FILE" 2>/dev/null || LOG_FILE=""
    : > "$ACTIONS_FILE" 2>/dev/null || ACTIONS_FILE=""
    [ -n "$ACTIONS_FILE" ] && printf 'module\tkind\tuser\tidentity\titem\tresult\n' >> "$ACTIONS_FILE"
}
log() {
    local level="$1"; shift
    local line; line="[$(date '+%Y-%m-%d %H:%M:%S')] [$(printf '%-5s' "$level")] $*"
    echo "$line"
    [ -n "$LOG_FILE" ] && echo "$line" >> "$LOG_FILE" 2>/dev/null
    case "$level" in
        WARN)  WARN_COUNT=$((WARN_COUNT + 1)) ;;
        ERROR) ERROR_COUNT=$((ERROR_COUNT + 1)) ;;
    esac
    return 0
}
# Counters are lost inside subshells and pipes, so anything that needs to count writes here.
bump() { # bump <var> <n>
    case "$1" in
        removed) ITEMS_REMOVED=$((ITEMS_REMOVED + ${2:-1})) ;;
        kept)    ITEMS_KEPT=$((ITEMS_KEPT + ${2:-1})) ;;
        warn)    WARN_COUNT=$((WARN_COUNT + ${2:-1})) ;;
        error)   ERROR_COUNT=$((ERROR_COUNT + ${2:-1})) ;;
    esac
}
act() { # act module kind user identity item result
    [ -n "$ACTIONS_FILE" ] || return 0
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" >> "$ACTIONS_FILE" 2>/dev/null
    return 0
}
section() { log STEP "------------------------------------------------------------------------------"
            log STEP "  $*"
            log STEP "------------------------------------------------------------------------------"; }
fmt_bytes() {
    local b="${1:-0}"
    if   [ "$b" -ge 1073741824 ]; then echo "$((b / 1073741824)) GB"
    elif [ "$b" -ge 1048576 ];    then echo "$((b / 1048576)) MB"
    elif [ "$b" -ge 1024 ];       then echo "$((b / 1024)) KB"
    else echo "${b} B"; fi
}
lc() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# ============================================================================================
#  THE SAFETY GATE
#  Same contract as the Windows script: an exact suffix match on @domain, never a substring.
#    Manav@delta.mainettigroup.onmicrosoft.com          -> match
#    Mitigata.Manav@delta.mainettigroup.onmicrosoft.com -> match   (local part is irrelevant)
#    x@notdelta.mainettigroup.onmicrosoft.com           -> no
#    x@sub.delta.mainettigroup.onmicrosoft.com          -> no
#    x@delta.mainettigroup.onmicrosoft.com.evil.net     -> no
#    abhishek@mainetti.com                              -> no
# ============================================================================================
upn_is_target() {
    local upn="$1" suffix d
    [ -n "$upn" ] || return 1
    case "$upn" in *@*) : ;; *) return 1 ;; esac
    suffix=$(lc "${upn##*@}")
    [ -n "$suffix" ] || return 1
    for d in $TARGET_DOMAINS; do
        [ "$suffix" = "$(lc "$d")" ] && return 0
    done
    return 1
}
# Looser check for opaque blobs and file contents, where there is no clean UPN field.
# Used to DECIDE only when a whole file or record belongs to one account; every path that
# reaches it is logged, and a file that names two tenants is reported rather than removed.
text_names_target() {
    local t d
    [ -n "${1:-}" ] || return 1
    t=$(lc "$1")
    for d in $TARGET_DOMAINS; do
        [ -n "$d" ] || continue
        case "$t" in *"$(lc "$d")"*) return 0 ;; esac
    done
    if [ -n "$OLD_TENANT_ID" ]; then
        case "$t" in *"$(lc "$OLD_TENANT_ID")"*) return 0 ;; esac
    fi
    return 1
}
text_names_other_tenant() {
    # True when the text names an account that is NOT the target - used to refuse removal
    # of anything shared between tenants.
    local t d
    [ -n "${1:-}" ] || return 1
    t=$(lc "$1")
    [ -n "$NEW_TENANT_ID" ] && case "$t" in *"$(lc "$NEW_TENANT_ID")"*) return 0 ;; esac
    # any address whose domain is not a target domain
    local addr
    for addr in $(printf '%s' "$1" | grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' 2>/dev/null | sort -u); do
        upn_is_target "$addr" || return 0
    done
    return 1
}
file_names_target() {
    # Handles plain text, JSON, and binary plists.
    local f="$1" d
    [ -f "$f" ] || return 1
    for d in $TARGET_DOMAINS; do
        grep -qai -- "$d" "$f" 2>/dev/null && return 0
    done
    [ -n "$OLD_TENANT_ID" ] && grep -qai -- "$OLD_TENANT_ID" "$f" 2>/dev/null && return 0
    case "$f" in
        *.plist)
            local xml; xml=$(plutil -convert xml1 -o - "$f" 2>/dev/null)
            [ -n "$xml" ] && text_names_target "$xml" && return 0 ;;
    esac
    return 1
}
file_names_other_tenant() {
    local f="$1" d found=1
    [ -f "$f" ] || return 1
    local addrs
    addrs=$(grep -oaE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$f" 2>/dev/null | sort -u)
    local a
    for a in $addrs; do
        upn_is_target "$a" || return 0
    done
    [ -n "$NEW_TENANT_ID" ] && grep -qai -- "$NEW_TENANT_ID" "$f" 2>/dev/null && return 0
    return 1
}

# ============================================================================================
#  DATA GUARDS
# ============================================================================================
MAIL_EXT_FIND=( -iname "*.olm" -o -iname "*.pst" -o -iname "*.mbox" -o -iname "*.eml" -o -iname "*.emlx" )

path_is_safe() {
    local p="$1" home="$2"
    [ -n "$p" ] || return 1
    [ -n "$home" ] || return 1
    [ "$home" != "/" ] || return 1
    case "$home" in
        /Users/*) : ;;
        *) [ "${PMC_ALLOW_NONSTANDARD_HOME:-0}" = "1" ] || return 1 ;;
    esac
    p="${p%/}"; home="${home%/}"
    [ -n "$p" ] || return 1
    [ "$p" = "$home" ] && return 1
    case "$p" in "$home"/*) : ;; *) return 1 ;; esac
    case "$p" in *"/../"*|*"/.."|*"/./"*) return 1 ;; esac
    local leaf
    for leaf in Documents Desktop Downloads Pictures Movies Music Public Applications; do
        case "$p" in "$home/$leaf"|"$home/$leaf"/*) return 1 ;; esac
    done
    case "$p" in
        "$home/Library/CloudStorage"|"$home/Library/CloudStorage"/*) return 1 ;;
        "$home/OneDrive"*|"$home/Library/Mobile Documents"*) return 1 ;;
    esac
    # Never a path that still holds mail data. Archives are rescued first by design; if any
    # remain when we get here, refuse rather than take the chance.
    if [ -d "$p" ]; then
        local m
        m=$(find "$p" -type f \( "${MAIL_EXT_FIND[@]}" \) -print -quit 2>/dev/null)
        if [ -n "$m" ]; then
            log WARN "GUARD: mail data under this path ($(basename "$m")) - refusing: $p"
            return 1
        fi
    fi
    return 0
}
folder_size_kb() { local p="$1"; [ -e "$p" ] || { echo 0; return; }; du -sk "$p" 2>/dev/null | awk '{print $1+0}'; }

remove_path() {
    local p="$1" home="$2" desc="$3"
    if [ ! -e "$p" ] && [ ! -L "$p" ]; then log SKIP "$desc - not present."; return 0; fi
    if ! path_is_safe "$p" "$home"; then log ERROR "$desc - BLOCKED by safety guard: $p"; return 1; fi
    local kb; kb=$(folder_size_kb "$p")
    if [ "$DRY_RUN" = "1" ]; then log DRY "$desc - WOULD remove $p ($(fmt_bytes $((kb * 1024))))"; return 0; fi
    chflags -R nouchg "$p" 2>/dev/null
    if rm -rf "$p" 2>/dev/null && [ ! -e "$p" ]; then
        BYTES_FREED=$((BYTES_FREED + kb * 1024)); ITEMS_REMOVED=$((ITEMS_REMOVED + 1))
        log OK "$desc - removed ($(fmt_bytes $((kb * 1024))))"
    else
        log WARN "$desc - could not fully remove $p (locked; a restart releases it)."
        RESTART_RECOMMENDED=1
    fi
    return 0
}
clear_folder() {
    local p="$1" home="$2" desc="$3"
    if [ ! -d "$p" ]; then log SKIP "$desc - not present."; return 0; fi
    if ! path_is_safe "$p" "$home"; then log ERROR "$desc - BLOCKED by safety guard: $p"; return 1; fi
    local kb; kb=$(folder_size_kb "$p")
    if [ "$DRY_RUN" = "1" ]; then log DRY "$desc - WOULD clear $p ($(fmt_bytes $((kb * 1024))))"; return 0; fi
    chflags -R nouchg "$p" 2>/dev/null
    find "$p" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null
    local leftover; leftover=$(find "$p" -mindepth 1 -maxdepth 1 2>/dev/null | head -1)
    BYTES_FREED=$((BYTES_FREED + kb * 1024))
    if [ -z "$leftover" ]; then
        ITEMS_REMOVED=$((ITEMS_REMOVED + 1)); log OK "$desc - cleared ($(fmt_bytes $((kb * 1024))))"
    else
        log WARN "$desc - partially cleared, some items locked. A restart releases them."
        RESTART_RECOMMENDED=1
    fi
    return 0
}
backup_item() {
    # backup_item <path> <user> <tag>  -> copy into the run's backup folder before deleting
    local p="$1" owner="$2" tag="$3"
    [ "$DRY_RUN" = "1" ] && return 0
    [ -e "$p" ] || return 0
    local dest="$LOG_DIR/backup-$HOSTNAME_SHORT-$STAMP/$owner"
    mkdir -p "$dest" 2>/dev/null || return 1
    ditto "$p" "$dest/$tag-$(basename "$p")" 2>/dev/null || cp -R "$p" "$dest/$tag-$(basename "$p")" 2>/dev/null
    return 0
}
preserve_archives() {
    local dir="$1" home="$2" owner="$3"
    [ -d "$dir" ] || return 0
    local archives; archives=$(find "$dir" -type f \( "${MAIL_EXT_FIND[@]}" \) 2>/dev/null)
    [ -n "$archives" ] || return 0
    local dest="$home/Documents/Outlook Archives (preserved)/$STAMP"
    if [ "$DRY_RUN" = "1" ]; then
        printf '%s\n' "$archives" | while IFS= read -r f; do
            [ -n "$f" ] && log DRY "WOULD preserve mail archive: $f -> $dest/"
        done
        return 0
    fi
    mkdir -p "$dest" 2>/dev/null || { log ERROR "Could not create '$dest' - $dir will NOT be touched."; return 1; }
    local failed=0
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        local base target n; base=$(basename "$f"); target="$dest/$base"; n=1
        while [ -e "$target" ]; do target="$dest/${base%.*} ($n).${base##*.}"; n=$((n + 1)); done
        if mv "$f" "$target" 2>/dev/null; then log OK "PRESERVED mail archive: $base -> $target"
        else log ERROR "Could not rescue '$f' - its parent will NOT be removed."; failed=1; fi
    done <<EOF_ARCH
$archives
EOF_ARCH
    chown -R "$owner" "$home/Documents/Outlook Archives (preserved)" 2>/dev/null
    return $failed
}

# ============================================================================================
#  USER AND SESSION RESOLUTION
#  Never $HOME - under an RMM that is /var/root and every deletion silently misses.
# ============================================================================================
get_console_user() {
    local u
    u=$(echo "show State:/Users/ConsoleUser" | scutil 2>/dev/null | awk '/Name :/ && ! /loginwindow/ { print $3 }')
    if [ -n "$u" ] && [ "$u" != "root" ] && [ "$u" != "loginwindow" ]; then
        CONSOLE_USER="$u"; CONSOLE_UID=$(id -u "$u" 2>/dev/null || echo "")
    fi
}
list_local_users() { dscl . -list /Users UniqueID 2>/dev/null | awk '$2 >= 500 && $1 !~ /^_/ {print $1}'; }
user_home()        { dscl . -read "/Users/$1" NFSHomeDirectory 2>/dev/null | awk '{print $2; exit}'; }
run_as_user()      { local u="$1" uid="$2"; shift 2; launchctl asuser "$uid" sudo -u "$u" "$@" 2>/dev/null; }

# ============================================================================================
#  APPLICATION SHUTDOWN
# ============================================================================================
quit_apps() {
    section "CLOSE THE APPS THAT HOLD THESE ACCOUNTS"
    local gui_apps=( "Microsoft Word" "Microsoft Excel" "Microsoft PowerPoint" "Microsoft Outlook"
                     "Microsoft OneNote" "Microsoft Teams" "Microsoft Teams classic"
                     "Microsoft Teams (work or school)" "OneDrive" "Company Portal" )
    if has_module DeltaBrowser || has_module BrowserAll; then
        gui_apps+=( "Safari" "Google Chrome" "Microsoft Edge" )
    fi
    # -f matches the whole command line, so every pattern here is specific enough not to
    # catch an unrelated process that merely mentions the word.
    local kill_patterns=( "/Microsoft Word.app" "/Microsoft Excel.app" "/Microsoft PowerPoint.app"
                          "/Microsoft Outlook.app" "/Microsoft OneNote.app" "com.microsoft.teams2"
                          "/Microsoft Teams" "/OneDrive.app" "/Company Portal.app"
                          "com.microsoft.OneDriveStandaloneUpdater" "/Microsoft AutoUpdate.app" )
    if has_module DeltaBrowser || has_module BrowserAll; then
        kill_patterns+=( "/Google Chrome.app" "/Microsoft Edge.app" "/Safari.app" )
    fi
    if [ "$DRY_RUN" = "1" ]; then log DRY "WOULD quit: ${gui_apps[*]}"; return 0; fi

    if [ "$FORCE" != "1" ] && [ -n "$CONSOLE_USER" ] && [ -n "$CONSOLE_UID" ]; then
        local app
        for app in "${gui_apps[@]}"; do
            run_as_user "$CONSOLE_USER" "$CONSOLE_UID" \
                osascript -e "tell application \"$app\" to if it is running then quit" >/dev/null 2>&1
        done
        log INFO "Graceful quit requested. Waiting up to ${GRACE}s..."
        local waited=0
        while [ "$waited" -lt "$GRACE" ]; do
            pgrep -f "com.microsoft.teams2|/Microsoft (Word|Excel|PowerPoint|Outlook|OneNote).app|/OneDrive.app" >/dev/null 2>&1 || break
            sleep 2; waited=$((waited + 2))
        done
    fi
    local pat
    for pat in "${kill_patterns[@]}"; do pkill -TERM -f "$pat" 2>/dev/null; done
    sleep 3
    for pat in "${kill_patterns[@]}"; do pkill -KILL -f "$pat" 2>/dev/null; done
    sleep 1
    log OK "Target applications closed."
    return 0
}

# ============================================================================================
#  KEYCHAIN INVENTORY
#  "security dump-keychain" without -d lists ATTRIBUTES ONLY. It never reads or prints a
#  secret and never raises an access prompt, which is what makes a per-item decision possible
#  in an unattended run. v2 deleted by hard-coded label, which is why it took the new tenant's
#  tokens - and why it deleted the item labelled "Exchange", which Apple Mail also uses.
# ============================================================================================
# One record per item: class \t label \t acct \t svce \t srvr.
# Held in a variable so the test suite exercises this exact program rather than a copy.
KC_AWK='
    function val(line) {
        sub(/^[^=]*=/, "", line)
        # security prints non-printable blobs as: 0x4D6963  "Micro". Unwrap that BEFORE
        # stripping quotes, or the trailing quote is gone and the pattern never matches.
        if (line ~ /^0x[0-9A-Fa-f]+  ".*"$/) { sub(/^0x[0-9A-Fa-f]+  "/, "", line); sub(/"$/, "", line) }
        else { gsub(/^"|"$/, "", line) }
        if (line == "<NULL>") line = ""
        gsub(/\t/, " ", line); return line }
    /^keychain: /              { if (have) print cls "\t" labl "\t" acct "\t" svce "\t" srvr
                                 have=1; cls=""; labl=""; acct=""; svce=""; srvr="" }
    /^class: /                 { cls=$2; gsub(/"/, "", cls) }
    /0x00000007 <blob>=/       { labl=val($0) }
    /"acct"<blob>=/            { acct=val($0) }
    /"svce"<blob>=/            { svce=val($0) }
    /"srvr"<blob>=/            { srvr=val($0) }
    END                        { if (have) print cls "\t" labl "\t" acct "\t" svce "\t" srvr }
'
kc_inventory() {
    # kc_inventory <user> <uid> <keychain>
    local u="$1" uid="$2" kc="$3"
    run_as_user "$u" "$uid" security dump-keychain "$kc" 2>/dev/null | awk "$KC_AWK"
}
kc_is_protected_label() {
    # Deleting these destroys data the user typed: browser password stores, and Apple's own
    # Exchange/Internet Accounts entries. Never touched, whatever else matches.
    case "$(lc "$1")" in
        *"chrome safe storage"*|*"chromium safe storage"*|*"microsoft edge safe storage"*) return 0 ;;
        "exchange"|"exchange account"|*"apple id"*|*"icloud"*) return 0 ;;
    esac
    return 1
}
kc_delete_item() {
    # kc_delete_item <user> <uid> <kc> <class> <label> <acct> <svce> <srvr>
    local u="$1" uid="$2" kc="$3" cls="$4" labl="$5" acct="$6" svce="$7" srvr="$8"
    local rc=1
    if [ "$cls" = "inet" ]; then
        if [ -n "$srvr" ] && [ -n "$acct" ]; then run_as_user "$u" "$uid" security delete-internet-password -s "$srvr" -a "$acct" "$kc" >/dev/null 2>&1 && rc=0
        elif [ -n "$srvr" ];                then run_as_user "$u" "$uid" security delete-internet-password -s "$srvr" "$kc" >/dev/null 2>&1 && rc=0; fi
    else
        if   [ -n "$svce" ] && [ -n "$acct" ]; then run_as_user "$u" "$uid" security delete-generic-password -s "$svce" -a "$acct" "$kc" >/dev/null 2>&1 && rc=0
        elif [ -n "$acct" ];                   then run_as_user "$u" "$uid" security delete-generic-password -a "$acct" "$kc" >/dev/null 2>&1 && rc=0
        elif [ -n "$svce" ];                   then run_as_user "$u" "$uid" security delete-generic-password -s "$svce" "$kc" >/dev/null 2>&1 && rc=0
        elif [ -n "$labl" ];                   then run_as_user "$u" "$uid" security delete-generic-password -l "$labl" "$kc" >/dev/null 2>&1 && rc=0; fi
    fi
    return $rc
}

# ============================================================================================
#  MODULE: DeltaKeychain                                                            DELTA ONLY
# ============================================================================================
mod_delta_keychain() {
    local u="$1" uid="$2" home="$3"
    section "DELTA KEYCHAIN - $u"
    local kc="$home/Library/Keychains/login.keychain-db"
    [ -f "$kc" ] || { log WARN "login.keychain-db not found for $u - skipped."; return 0; }

    local inv; inv=$(kc_inventory "$u" "$uid" "$kc")
    if [ -z "$inv" ]; then
        log WARN "Could not read the keychain inventory for $u."
        log WARN "The login keychain must be unlocked and this must run in their session."
        return 0
    fi
    local total hit=0 kept=0
    total=$(printf '%s\n' "$inv" | grep -c . )
    log INFO "Keychain items visible: $total"

    local tmp; tmp=$(mktemp /tmp/pmc-kc.XXXXXX) || return 0
    printf '%s\n' "$inv" > "$tmp"
    while IFS=$'\t' read -r cls labl acct svce srvr; do
        [ -n "$cls" ] || continue
        local blob="$labl $acct $svce $srvr"
        if ! text_names_target "$blob"; then kept=$((kept + 1)); continue; fi
        if kc_is_protected_label "$labl"; then
            log KEEP "protected item, never removed: '$labl'"; kept=$((kept + 1)); continue
        fi
        if text_names_other_tenant "$blob"; then
            log KEEP "names another tenant as well, left alone: '$labl' / '$acct'"; kept=$((kept + 1)); continue
        fi
        hit=$((hit + 1))
        if [ "$DRY_RUN" = "1" ]; then
            log DRY "WOULD delete keychain item  [$cls] '$labl'  acct='$acct'  svce='$svce$srvr'"
            act DeltaKeychain keychain "$u" "$acct" "$labl" "WOULD REMOVE"; continue
        fi
        if kc_delete_item "$u" "$uid" "$kc" "$cls" "$labl" "$acct" "$svce" "$srvr"; then
            log OK "deleted keychain item  [$cls] '$labl'  acct='$acct'"
            ITEMS_REMOVED=$((ITEMS_REMOVED + 1)); act DeltaKeychain keychain "$u" "$acct" "$labl" REMOVED
        else
            log WARN "could not delete '$labl' / '$acct' - it may be locked by a running app."
        fi
    done < "$tmp"
    rm -f "$tmp" 2>/dev/null
    ITEMS_KEPT=$((ITEMS_KEPT + kept))
    log INFO "Naming the old tenant : $hit"
    log KEEP "Every other item kept : $kept"
    [ "$hit" = "0" ] && log OK "No keychain item on this Mac names the old tenant."
    return 0
}

# ============================================================================================
#  MODULE: DeltaTokens   -   OneAuth / MSAL account files, per file                 DELTA ONLY
# ============================================================================================
mod_delta_tokens() {
    local home="$1" u="$2"
    section "DELTA TOKEN STORE - $u"
    local roots="$home/Library/Group Containers/UBF8T346G9.com.microsoft.oneauth
$home/Library/Application Scripts/UBF8T346G9.com.microsoft.oneauth
$home/Library/Group Containers/UBF8T346G9.Office/MicrosoftIdentityCacheV2"
    local hit=0 kept=0 root
    while IFS= read -r root; do
        [ -d "$root" ] || continue
        local f
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            if ! file_names_target "$f"; then kept=$((kept + 1)); continue; fi
            if file_names_other_tenant "$f"; then
                log KEEP "shared file names another tenant too, left alone: $f"
                kept=$((kept + 1)); continue
            fi
            hit=$((hit + 1))
            if [ "$DRY_RUN" = "1" ]; then log DRY "WOULD remove token file: $f"
                                         act DeltaTokens tokenfile "$u" "" "$f" "WOULD REMOVE"; continue; fi
            backup_item "$f" "$u" oneauth
            remove_path "$f" "$home" "OneAuth entry $(basename "$f")"
            act DeltaTokens tokenfile "$u" "" "$f" REMOVED
        done <<EOF_F
$(find "$root" -type f 2>/dev/null)
EOF_F
    done <<EOF_R
$roots
EOF_R
    ITEMS_KEPT=$((ITEMS_KEPT + kept))
    log INFO "Token files naming the old tenant : $hit"
    log KEEP "Left in place                     : $kept"
    if [ "$hit" = "0" ]; then
        log OK "No OneAuth entry names the old tenant."
        log INFO "If an account still shows in an app picker, its entry is in the data-protection"
        log INFO "keychain - use --modules TokenStoreAll, which signs every account out."
    fi
    return 0
}

# ============================================================================================
#  MODULE: DeltaOffice                                                             DELTA ONLY
# ============================================================================================
mod_delta_office() {
    local home="$1" u="$2" uid="$3"
    section "DELTA OFFICE IDENTITY AND LICENCE - $u"
    local gc="$home/Library/Group Containers/UBF8T346G9.Office"
    local hit=0 kept=0 d f
    for d in "$gc/Identity" "$gc/Licenses" "$gc/mip_policy"; do
        [ -d "$d" ] || continue
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            if ! file_names_target "$f"; then kept=$((kept + 1)); continue; fi
            if file_names_other_tenant "$f"; then
                log KEEP "shared, names another tenant too: $f"; kept=$((kept + 1)); continue; fi
            hit=$((hit + 1))
            if [ "$DRY_RUN" = "1" ]; then log DRY "WOULD remove Office entry: $f"
                                         act DeltaOffice office "$u" "" "$f" "WOULD REMOVE"; continue; fi
            backup_item "$f" "$u" office
            remove_path "$f" "$home" "Office entry $(basename "$f")"
            act DeltaOffice office "$u" "" "$f" REMOVED
        done <<EOF_OF
$(find "$d" -type f 2>/dev/null)
EOF_OF
    done
    # The sign-in hint that pre-fills the old address. Cleared only when it IS the old address.
    local hint="$home/Library/Preferences/com.microsoft.msa-login-hint.plist"
    if [ -f "$hint" ] && file_names_target "$hint"; then
        hit=$((hit + 1)); backup_item "$hint" "$u" hint
        remove_path "$hint" "$home" "MSA login hint (names the old tenant)"
    elif [ -f "$hint" ]; then
        log KEEP "MSA login hint does not name the old tenant - kept."; kept=$((kept + 1))
    fi
    if [ -n "$uid" ]; then
        local act_email; act_email=$(run_as_user "$u" "$uid" defaults read com.microsoft.office OfficeActivationEmailAddress 2>/dev/null)
        if [ -n "$act_email" ] && upn_is_target "$act_email"; then
            if [ "$DRY_RUN" = "1" ]; then log DRY "WOULD clear OfficeActivationEmailAddress ($act_email)"
            else run_as_user "$u" "$uid" defaults delete com.microsoft.office OfficeActivationEmailAddress >/dev/null 2>&1
                 run_as_user "$u" "$uid" killall cfprefsd >/dev/null 2>&1
                 log OK "Cleared OfficeActivationEmailAddress ($act_email)"; ITEMS_REMOVED=$((ITEMS_REMOVED + 1)); fi
        elif [ -n "$act_email" ]; then
            log KEEP "OfficeActivationEmailAddress is $act_email - not the old tenant, kept."; kept=$((kept + 1))
        fi
    fi
    ITEMS_KEPT=$((ITEMS_KEPT + kept))
    log INFO "Office entries naming the old tenant : $hit"
    log KEEP "Left in place                        : $kept"
    log KEEP "ResetOneAuthCreds is NOT set here - it wipes every account, not just the old one."
    return 0
}

# ============================================================================================
#  MODULE: DeltaOneDrive                                                           DELTA ONLY
#  Only the BusinessN binding that names the old tenant. Synced files are never touched.
# ============================================================================================
mod_delta_onedrive() {
    local home="$1" u="$2"
    section "DELTA ONEDRIVE - $u"
    log INFO "Synced FILES on disk are never touched - only the account binding."
    local bases="$home/Library/Application Support/OneDrive/settings
$home/Library/Containers/com.microsoft.OneDrive-mac/Data/Library/Application Support/OneDrive/settings"
    local hit=0 kept=0 base b
    while IFS= read -r base; do
        [ -d "$base" ] || continue
        for b in "$base"/Business*; do
            [ -d "$b" ] || continue
            local names_target=0 names_other=0 f
            while IFS= read -r f; do
                [ -n "$f" ] || continue
                file_names_target "$f" && names_target=1
                file_names_other_tenant "$f" && names_other=1
            done <<EOF_OD
$(find "$b" -type f -size -4m 2>/dev/null)
EOF_OD
            if [ "$names_target" = "0" ]; then
                log KEEP "$(basename "$b") does not name the old tenant - kept."; kept=$((kept + 1)); continue
            fi
            if [ "$names_other" = "1" ]; then
                log WARN "$(basename "$b") names BOTH tenants - left alone. Unlink it from the OneDrive menu."
                kept=$((kept + 1)); continue
            fi
            hit=$((hit + 1))
            if [ "$DRY_RUN" = "1" ]; then log DRY "WOULD unlink $(basename "$b") ($base)"
                                         act DeltaOneDrive onedrive "$u" "" "$b" "WOULD REMOVE"; continue; fi
            backup_item "$b" "$u" onedrive
            remove_path "$b" "$home" "OneDrive binding $(basename "$b")"
            act DeltaOneDrive onedrive "$u" "" "$b" REMOVED
        done
    done <<EOF_OB
$bases
EOF_OB
    ITEMS_KEPT=$((ITEMS_KEPT + kept))
    [ "$hit" = "0" ] && log OK "No OneDrive binding on this Mac belongs to the old tenant."
    return 0
}

# ============================================================================================
#  MODULE: DeltaBrowser                                                            DELTA ONLY
#  A browser profile is cleared only when EVERY signed-in address in it is the old tenant.
#  A mixed profile is reported and left alone - clearing it signs the other account out too.
# ============================================================================================
mod_delta_browser() {
    local home="$1" u="$2"
    section "DELTA BROWSER PROFILE - $u"
    local pairs="Google/Chrome|Google Chrome
Microsoft Edge|Microsoft Edge
BraveSoftware/Brave-Browser|Brave"
    local any=0 line rel name base cbase p
    while IFS= read -r line; do
        rel="${line%%|*}"; name="${line##*|}"
        base="$home/Library/Application Support/$rel"
        cbase="$home/Library/Caches/$rel"
        [ -d "$base" ] || continue
        for p in "$base/Default" "$base"/Profile\ *; do
            [ -d "$p" ] || continue
            local pref="$p/Preferences"
            [ -f "$pref" ] || continue
            local mails tgt=0 oth=0 m
            mails=$(grep -oaE '"email":"[^"]+"' "$pref" 2>/dev/null | sed 's/"email":"//; s/"$//' | sort -u)
            [ -n "$mails" ] || continue
            any=1
            for m in $mails; do
                if upn_is_target "$m"; then tgt=1; else oth=1; fi
            done
            if [ "$tgt" = "0" ]; then
                log KEEP "$name / $(basename "$p") signed in as: $(echo "$mails" | tr '\n' ' ') - kept."
                ITEMS_KEPT=$((ITEMS_KEPT + 1)); continue
            fi
            if [ "$oth" = "1" ]; then
                log WARN "$name / $(basename "$p") holds BOTH tenants: $(echo "$mails" | tr '\n' ' ')"
                log WARN "  left alone - clearing it would sign the other account out too."
                log WARN "  Remove the old profile from the browser's own profile menu."
                ITEMS_KEPT=$((ITEMS_KEPT + 1))
                act DeltaBrowser browser "$u" "" "$name/$(basename "$p")" "SKIPPED-MIXED"; continue
            fi
            log INFO "$name / $(basename "$p") is signed in only as the old tenant - clearing its session."
            local ff dd
            for ff in "Network/Cookies" "Network/Cookies-journal" "Cookies" "Cookies-journal" \
                      "Current Session" "Current Tabs" "Last Session" "Last Tabs"; do
                [ -f "$p/$ff" ] && remove_path "$p/$ff" "$home" "$name/$(basename "$p") - $ff"
            done
            # Microsoft web apps keep MSAL refresh tokens in Local Storage and IndexedDB, not
            # in cookies. Clearing cookies alone leaves the browser silently signed in.
            for dd in "Sessions" "Session Storage" "Local Storage/leveldb" "IndexedDB" \
                      "Service Worker/CacheStorage" "Service Worker/ScriptCache" "GPUCache"; do
                [ -d "$p/$dd" ] && clear_folder "$p/$dd" "$home" "$name/$(basename "$p") - $dd"
            done
            for dd in "Cache" "Code Cache" "GPUCache"; do
                [ -d "$cbase/$(basename "$p")/$dd" ] && clear_folder "$cbase/$(basename "$p")/$dd" "$home" "$name/$(basename "$p") - cache/$dd"
            done
            log KEEP "  bookmarks, saved passwords, autofill, extensions and history preserved."
            act DeltaBrowser browser "$u" "" "$name/$(basename "$p")" CLEARED
        done
    done <<EOF_BR
$pairs
EOF_BR
    [ "$any" = "0" ] && log OK "No browser profile on this Mac is signed in to a work account."
    return 0
}

# ============================================================================================
#  MODULE: DeltaSSO                                                                DELTA ONLY
#  The Microsoft Enterprise SSO extension holds the Mac's shared broker token - the closest
#  thing to a Windows PRT. v2 never touched it, which is the most likely reason an account
#  kept reappearing on Macs that looked clean everywhere else.
# ============================================================================================
mod_delta_sso() {
    local u="$1" uid="$2"
    section "MICROSOFT ENTERPRISE SSO EXTENSION - $u"
    if [ ! -x /usr/bin/app-sso ]; then
        log SKIP "app-sso not present on this macOS build - nothing to inspect."
        return 0
    fi
    local listing; listing=$(run_as_user "$u" "$uid" /usr/bin/app-sso -l 2>&1)
    if [ -z "$listing" ]; then
        listing=$(run_as_user "$u" "$uid" /usr/bin/app-sso platformsso -s 2>&1)
    fi
    if [ -z "$listing" ]; then log SKIP "No SSO extension session reported."; return 0; fi
    log INFO "app-sso reports:"
    printf '%s\n' "$listing" | while IFS= read -r l; do [ -n "$l" ] && log INFO "   $l"; done
    [ -n "$LOG_FILE" ] && printf '%s\n' "$listing" > "$LOG_DIR/app-sso-$HOSTNAME_SHORT-$STAMP.txt" 2>/dev/null

    if ! text_names_target "$listing"; then
        log OK "The SSO extension does not hold a token for the old tenant."
        ITEMS_KEPT=$((ITEMS_KEPT + 1)); return 0
    fi
    log WARN "The SSO extension IS holding old-tenant state. This is what hands the account"
    log WARN "back to every app, so it must go for the removal to stick."
    if [ "$DRY_RUN" = "1" ]; then
        log DRY "WOULD ask app-sso to drop the old-tenant SSO tokens."
        act DeltaSSO sso "$u" "" "app-sso" "WOULD REMOVE"; return 0
    fi
    # Flags differ between macOS releases, so only use one the installed binary advertises.
    local help; help=$(run_as_user "$u" "$uid" /usr/bin/app-sso --help 2>&1)
    local done_any=0 realm
    for realm in $(printf '%s' "$listing" | grep -oE '[A-Za-z0-9._-]+\.(onmicrosoft\.com|com|net)' | sort -u); do
        text_names_target "$realm" || continue
        case "$help" in
            *"-d"*|*"--delete"*)
                if run_as_user "$u" "$uid" /usr/bin/app-sso -d "$realm" >/dev/null 2>&1; then
                    log OK "app-sso dropped SSO tokens for $realm"; ITEMS_REMOVED=$((ITEMS_REMOVED + 1))
                    act DeltaSSO sso "$u" "$realm" "app-sso -d" REMOVED; done_any=1
                fi ;;
        esac
    done
    if [ "$done_any" = "0" ]; then
        log WARN "This app-sso build has no delete flag. Do it by hand, in the user's session:"
        log WARN "   app-sso -l          # confirm the realm"
        log WARN "   app-sso -d <realm>  # if supported, otherwise sign out of Company Portal"
        log WARN "Then re-run this script. DeltaKeychain removes the extension's stored items."
    fi
    return 0
}

# ============================================================================================
#  MODULE: DeltaWorkAccount                                                        DELTA ONLY
#  Workplace Join records and the Entra device certificate are removed ONLY when something on
#  this Mac proves they belong to the old tenant. The tenant id itself lives in the keychain
#  item's DATA, and reading that raises an access prompt that would hang an unattended run -
#  so the proof comes from attributes and from the SSO/Company Portal state instead. With no
#  proof, this refuses and reports rather than guessing.
# ============================================================================================
mod_delta_workaccount() {
    local u="$1" uid="$2" home="$3"
    section "WORK ACCOUNT / ENTRA REGISTRATION - $u"
    local kc="$home/Library/Keychains/login.keychain-db"
    [ -f "$kc" ] || { log WARN "login.keychain-db not found - skipped."; return 0; }

    local evidence="" d
    local inv; inv=$(kc_inventory "$u" "$uid" "$kc" | grep -i workplacejoin)
    [ -n "$inv" ] && evidence="$evidence
$inv"
    for d in "$home/Library/Application Support/com.microsoft.CompanyPortalMac" \
             "$home/Library/Containers/com.microsoft.CompanyPortalMac"; do
        [ -d "$d" ] || continue
        local g; g=$(grep -rail --include='*' -m1 -e "$(printf '%s' "$TARGET_DOMAINS" | awk '{print $1}')" "$d" 2>/dev/null | head -5)
        [ -n "$g" ] && evidence="$evidence
$g"
    done
    if [ -x /usr/bin/app-sso ]; then
        local ssol; ssol=$(run_as_user "$u" "$uid" /usr/bin/app-sso -l 2>&1)
        text_names_target "$ssol" && evidence="$evidence
app-sso reports old-tenant state"
    fi

    if [ -z "$(printf '%s' "$evidence" | tr -d ' \n')" ]; then
        log KEEP "No Workplace Join material on this Mac can be shown to belong to the old tenant."
        log KEEP "Refusing to remove it. On a Mac already registered to the NEW tenant this is"
        log KEEP "exactly the record you want to keep."
        ITEMS_KEPT=$((ITEMS_KEPT + 1)); return 0
    fi
    if text_names_other_tenant "$evidence"; then
        log WARN "Workplace Join evidence names another tenant too - refusing to remove it."
        ITEMS_KEPT=$((ITEMS_KEPT + 1)); return 0
    fi
    log WARN "Workplace Join material traced to the old tenant. Removing."
    printf '%s\n' "$evidence" | while IFS= read -r l; do [ -n "$l" ] && log INFO "   evidence: $l"; done

    if [ "$DRY_RUN" = "1" ]; then
        log DRY "WOULD remove Workplace Join keychain records and the MS-ORGANIZATION-ACCESS identity."
        return 0
    fi
    local acct
    for acct in com.microsoft.workplacejoin.thumbprint \
                com.microsoft.workplacejoin.registeredUserPrincipalName \
                com.microsoft.workplacejoin.deviceOSVersion \
                com.microsoft.workplacejoin.devicePatchAttemptTimestamp \
                com.microsoft.workplacejoin.tenantId \
                com.microsoft.workplacejoin.tenantDisplayName \
                com.microsoft.workplacejoin.cloudEnvironment \
                com.microsoft.workplacejoin.deviceName ; do
        local n=0
        while run_as_user "$u" "$uid" security delete-generic-password -a "$acct" "$kc" >/dev/null 2>&1; do
            n=$((n + 1)); [ "$n" -ge 25 ] && break
        done
        [ "$n" -gt 0 ] && { log OK "removed $n Workplace Join record(s): $acct"; ITEMS_REMOVED=$((ITEMS_REMOVED + n)); }
    done
    # find-certificate -Z prints "SHA-1 hash:" then "SHA-256 hash:" ahead of each cert block,
    # so remember the SHA-1 and emit it when the issuer line goes past. delete-identity takes
    # the SHA-1 and removes the private key with the certificate; delete-certificate is the
    # fallback and leaves the key behind.
    local hashes h
    hashes=$(run_as_user "$u" "$uid" bash -c "security find-certificate -a -Z '$kc' 2>/dev/null | awk '/^SHA-1 hash: /{h=\$NF} /MS-ORGANIZATION-ACCESS/{if(h!=\"\"){print h; h=\"\"}}'")
    if [ -z "$hashes" ]; then
        log SKIP "No MS-ORGANIZATION-ACCESS certificate found."
    else
        while IFS= read -r h; do
            [ -n "$h" ] || continue
            if run_as_user "$u" "$uid" security delete-identity -Z "$h" "$kc" >/dev/null 2>&1; then
                log OK "Removed the Entra device identity, certificate and key ($h)."
                ITEMS_REMOVED=$((ITEMS_REMOVED + 1))
            elif run_as_user "$u" "$uid" security delete-certificate -Z "$h" -t "$kc" >/dev/null 2>&1; then
                log OK "Removed the Entra device certificate ($h). The private key may remain."
                ITEMS_REMOVED=$((ITEMS_REMOVED + 1))
            else
                log WARN "Found the Entra device certificate $h but could not remove it."
            fi
        done <<EOF_CERT
$hashes
EOF_CERT
    fi
    log INFO "Reminder: delete the stale device object in the OLD tenant (Entra admin centre > Devices)."
    return 0
}

# ============================================================================================
#  MODULE: AppCache                                                                CACHE ONLY
#  Scratch only. No token store, no account list, nothing signs out.
# ============================================================================================
mod_app_cache() {
    local home="$1" u="$2"
    section "APP CACHE - $u  (nothing signs out)"
    local ct="$home/Library/Containers" appid ss
    for appid in com.microsoft.Word com.microsoft.Excel com.microsoft.Powerpoint com.microsoft.onenote.mac; do
        clear_folder "$ct/$appid/Data/Library/Caches" "$home" "$appid cache"
    done
    clear_folder "$home/Library/Caches/com.microsoft.teams"   "$home" "Classic Teams cache"
    clear_folder "$home/Library/Caches/com.microsoft.OneDrive" "$home" "OneDrive cache"
    clear_folder "$home/Library/Caches/com.microsoft.CompanyPortalMac" "$home" "Company Portal cache"
    clear_folder "$home/Library/Caches/com.microsoft.Outlook" "$home" "Outlook cache"
    for ss in "$home/Library/Saved Application State"/com.microsoft.*.savedState; do
        [ -e "$ss" ] || continue
        remove_path "$ss" "$home" "saved window state $(basename "$ss")"
    done
    log KEEP "Token stores, account lists, Outlook profile and OneDrive bindings untouched."
    return 0
}

# ============================================================================================
#  MODULE: OutlookCache                                                            CACHE ONLY
#  Container caches only. Never the profile database, never mail.
# ============================================================================================
mod_outlook_cache() {
    local home="$1" u="$2"
    section "OUTLOOK CACHE - $u  (profile and mail untouched)"
    local ctd="$home/Library/Containers/com.microsoft.Outlook/Data/Library"
    clear_folder "$ctd/Caches" "$home" "Outlook container caches"
    clear_folder "$ctd/WebKit" "$home" "Outlook embedded-webview data"
    remove_path  "$home/Library/Containers/com.microsoft.Outlook.CalendarWidget" "$home" "Outlook calendar widget container"
    remove_path  "$home/Library/HTTPStorages/com.microsoft.Outlook" "$home" "Outlook HTTP storage"
    log KEEP "The profile at Group Containers/UBF8T346G9.Office/Outlook is NOT touched here."
    log KEEP "That database holds 'On My Computer' local mail, which cannot be separated from"
    log KEEP "the old tenant's cache at file level. Use --modules OutlookProfileAll if you"
    log KEEP "really need it reset - it is moved to a backup folder, never deleted."
    return 0
}

# ============================================================================================
#  ALL-ACCOUNT MODULES  -  gated behind --i-accept-all-account-impact
# ============================================================================================
mod_token_store_all() {
    local u="$1" uid="$2" home="$3"
    section "TOKEN STORE - ALL ACCOUNTS, NOT JUST THE OLD TENANT - $u"
    log WARN "Every work account on this Mac will have to sign in again."
    remove_path "$home/Library/Group Containers/UBF8T346G9.com.microsoft.oneauth" "$home" "OneAuth token store (all accounts)"
    remove_path "$home/Library/Application Scripts/UBF8T346G9.com.microsoft.oneauth" "$home" "OneAuth application scripts"
    # The data-protection keychain holds the account list the app pickers show. Editing it
    # directly is unsupported and needs Full Disk Access; sqlite3 also exits 0 when it matches
    # nothing, so the row count is checked rather than the exit code.
    local kc2; kc2=$(find "$home/Library/Keychains" -maxdepth 2 -name "keychain-2.db" 2>/dev/null | head -1)
    if [ -n "$kc2" ] && [ -f "$kc2" ]; then
        if [ "$DRY_RUN" = "1" ]; then
            local n; n=$(sqlite3 "$kc2" "SELECT COUNT(*) FROM genp WHERE agrp='UBF8T346G9.com.microsoft.identity.universalstorage';" 2>/dev/null)
            log DRY "WOULD purge ${n:-?} OneAuth account row(s) from the data-protection keychain."
        else
            local before after
            before=$(sqlite3 "$kc2" "SELECT COUNT(*) FROM genp WHERE agrp='UBF8T346G9.com.microsoft.identity.universalstorage';" 2>/dev/null)
            sqlite3 "$kc2" "DELETE FROM genp WHERE agrp='UBF8T346G9.com.microsoft.identity.universalstorage';" 2>/dev/null
            after=$(sqlite3 "$kc2" "SELECT COUNT(*) FROM genp WHERE agrp='UBF8T346G9.com.microsoft.identity.universalstorage';" 2>/dev/null)
            if [ -n "$before" ] && [ -n "$after" ] && [ "$before" -gt "$after" ] 2>/dev/null; then
                log OK "Purged $((before - after)) OneAuth account row(s) - app pickers will be empty."
                ITEMS_REMOVED=$((ITEMS_REMOVED + before - after))
            elif [ "${before:-0}" = "0" ]; then
                log INFO "No OneAuth rows present - nothing to purge."
            else
                log WARN "Could not purge the OneAuth rows (Full Disk Access or a lock). Nothing changed."
                log WARN "Staging ResetOneAuthCreds instead - it clears the list at next app launch."
                local dom
                for dom in com.microsoft.Word com.microsoft.Excel com.microsoft.Powerpoint \
                           com.microsoft.Outlook com.microsoft.onenote.mac com.microsoft.teams2; do
                    run_as_user "$u" "$uid" defaults write "$dom" ResetOneAuthCreds -bool YES >/dev/null 2>&1
                done
                run_as_user "$u" "$uid" killall cfprefsd >/dev/null 2>&1
            fi
        fi
    else
        log SKIP "Data-protection keychain not found."
    fi
    return 0
}
mod_keychain_all() {
    local u="$1" uid="$2" home="$3"
    section "KEYCHAIN - ALL MICROSOFT ITEMS, EVERY TENANT - $u"
    local kc="$home/Library/Keychains/login.keychain-db"
    [ -f "$kc" ] || { log WARN "login.keychain-db not found - skipped."; return 0; }
    local tmp; tmp=$(mktemp /tmp/pmc-kca.XXXXXX) || return 0
    kc_inventory "$u" "$uid" "$kc" > "$tmp"
    while IFS=$'\t' read -r cls labl acct svce srvr; do
        [ -n "$cls" ] || continue
        local blob; blob=$(lc "$labl $acct $svce $srvr")
        case "$blob" in
            *microsoft*|*msopentech*|*adalcache*|*oneauth*|*onedrive*|*office*|*teams*|*msocredential*|*enterpriseregistration*) : ;;
            *) ITEMS_KEPT=$((ITEMS_KEPT + 1)); continue ;;
        esac
        if kc_is_protected_label "$labl"; then log KEEP "protected, never removed: '$labl'"; ITEMS_KEPT=$((ITEMS_KEPT + 1)); continue; fi
        if [ "$DRY_RUN" = "1" ]; then log DRY "WOULD delete [$cls] '$labl' acct='$acct'"; continue; fi
        kc_delete_item "$u" "$uid" "$kc" "$cls" "$labl" "$acct" "$svce" "$srvr" \
            && { log OK "deleted [$cls] '$labl'"; ITEMS_REMOVED=$((ITEMS_REMOVED + 1)); }
    done < "$tmp"
    rm -f "$tmp" 2>/dev/null
    return 0
}
mod_browser_all() {
    local home="$1" u="$2"
    section "BROWSER - ALL PROFILES, ALL SITES - $u"
    log WARN "This signs the user out of websites in every profile."
    local pairs="Google/Chrome|Google Chrome
Microsoft Edge|Microsoft Edge
BraveSoftware/Brave-Browser|Brave"
    local line rel name base cbase p ff dd
    while IFS= read -r line; do
        rel="${line%%|*}"; name="${line##*|}"
        base="$home/Library/Application Support/$rel"; cbase="$home/Library/Caches/$rel"
        [ -d "$base" ] || continue
        for p in "$base/Default" "$base"/Profile\ *; do
            [ -d "$p" ] || continue
            for ff in "Network/Cookies" "Network/Cookies-journal" "Cookies" "Cookies-journal" \
                      "Current Session" "Current Tabs" "Last Session" "Last Tabs"; do
                [ -f "$p/$ff" ] && remove_path "$p/$ff" "$home" "$name/$(basename "$p") - $ff"
            done
            for dd in "Sessions" "Session Storage" "Local Storage/leveldb" "IndexedDB" \
                      "Service Worker/CacheStorage" "Service Worker/ScriptCache" "GPUCache"; do
                [ -d "$p/$dd" ] && clear_folder "$p/$dd" "$home" "$name/$(basename "$p") - $dd"
            done
            for dd in "Cache" "Code Cache" "GPUCache"; do
                [ -d "$cbase/$(basename "$p")/$dd" ] && clear_folder "$cbase/$(basename "$p")/$dd" "$home" "$name/$(basename "$p") - cache/$dd"
            done
        done
    done <<EOF_BA
$pairs
EOF_BA
    # Safari's container is TCC-protected even from root.
    local sc="$home/Library/Containers/com.apple.Safari/Data/Library"
    if [ -d "$home/Library/Containers/com.apple.Safari" ]; then
        if ! ls "$sc" >/dev/null 2>&1; then
            log WARN "Safari data is TCC-protected and this process lacks Full Disk Access."
            log WARN "Grant FDA to the RMM agent (PPPC profile) and re-run to include Safari."
        else
            remove_path  "$sc/Cookies/Cookies.binarycookies" "$home" "Safari cookies"
            clear_folder "$sc/WebKit" "$home" "Safari WebKit site data (LocalStorage/IndexedDB/ServiceWorkers)"
            clear_folder "$sc/Caches" "$home" "Safari container caches"
            remove_path  "$sc/Safari/LastSession.plist" "$home" "Safari last session"
        fi
    fi
    log KEEP "Bookmarks, saved passwords, autofill, extensions and history preserved."
    return 0
}
mod_onedrive_all() {
    local home="$1" u="$2"
    section "ONEDRIVE - UNLINK EVERY BUSINESS ACCOUNT - $u"
    log WARN "Every OneDrive business link is removed, including the new tenant's."
    log INFO "Synced files on disk are never deleted."
    clear_folder "$home/Library/Application Support/OneDrive/settings" "$home" "OneDrive settings (standalone)"
    clear_folder "$home/Library/Containers/com.microsoft.OneDrive-mac/Data/Library/Application Support/OneDrive/settings" "$home" "OneDrive settings (App Store)"
    remove_path "$home/Library/Group Containers/UBF8T346G9.OneDriveStandaloneSuite" "$home" "OneDrive standalone suite state"
    remove_path "$home/Library/Group Containers/UBF8T346G9.OneDriveSyncClientSuite" "$home" "OneDrive sync client suite state"
    return 0
}
mod_outlook_profile_all() {
    local home="$1" u="$2"
    section "OUTLOOK PROFILE - ALL ACCOUNTS - $u"
    log WARN "This affects every mailbox on this Mac, not only the old tenant's."
    local gc="$home/Library/Group Containers/UBF8T346G9.Office"
    local profdir="$gc/Outlook" profplist="$gc/OutlookProfile.plist"
    [ -d "$profdir" ] || { log SKIP "Outlook profile data - not present."; return 0; }
    local backup="$home/Outlook Profile Backup (old tenant) $STAMP"
    if [ "$DRY_RUN" = "1" ]; then log DRY "WOULD move the Outlook profile to: $backup"; return 0; fi
    mkdir -p "$backup" 2>/dev/null || { log ERROR "Could not create '$backup' - profile left untouched."; return 0; }
    if mv "$profdir" "$backup/Outlook" 2>/dev/null; then
        ITEMS_REMOVED=$((ITEMS_REMOVED + 1))
        log OK "Outlook profile MOVED to backup - nothing deleted: $backup/Outlook"
        log INFO "Outlook runs first-time setup at next launch. To restore, move the folder back to"
        log INFO "~/Library/Group Containers/UBF8T346G9.Office/Outlook"
        [ -f "$profplist" ] && mv "$profplist" "$backup/OutlookProfile.plist" 2>/dev/null
        chown -R "$u" "$backup" 2>/dev/null
    else
        rmdir "$backup" 2>/dev/null
        log WARN "Could not move the Outlook profile (locked) - left untouched."
        RESTART_RECOMMENDED=1
    fi
    return 0
}
mod_company_portal_all() {
    local home="$1" u="$2"
    section "COMPANY PORTAL - ALL ACCOUNTS - $u"
    local p
    for p in "Application Support/com.microsoft.CompanyPortalMac" \
             "Application Support/com.microsoft.CompanyPortalMac.usercontext.info" \
             "Application Support/com.microsoft.CompanyPortal" \
             "Preferences/com.microsoft.CompanyPortalMac.plist" \
             "Preferences/group.com.microsoft.CompanyPortalMac.plist" \
             "Caches/CompanyPortalCache" \
             "Saved Application State/com.microsoft.CompanyPortalMac.savedState" \
             "Keychains/Microsoft_Entity_Certificates-db" ; do
        remove_path "$home/Library/$p" "$home" "Company Portal - $p"
    done
    local ck
    for ck in "$home/Library/Cookies"/com.microsoft.CompanyPortal*.binarycookies; do
        [ -e "$ck" ] && remove_path "$ck" "$home" "Company Portal cookies $(basename "$ck")"
    done
    return 0
}

# ============================================================================================
#  MDM state - report only, never removed
# ============================================================================================
report_mdm_state() {
    section "MDM ENROLMENT (report only)"
    command -v profiles >/dev/null 2>&1 || { log INFO "profiles tool unavailable - MDM state unknown."; return 0; }
    local status; status=$(profiles status -type enrollment 2>/dev/null)
    if [ -n "$status" ]; then
        printf '%s\n' "$status" | while IFS= read -r l; do [ -n "$l" ] && log INFO "   $l"; done
        printf '%s' "$status" | grep -qi "MDM enrollment: Yes" && \
            log WARN "Device reports MDM enrolment. This script never unenrols - retire it from the MDM console."
    else
        log INFO "No enrolment status reported (not MDM-enrolled)."
    fi
    return 0
}

# ============================================================================================
#  VERIFY  -  re-scan for the target domain after the run
# ============================================================================================
verify_user() {
    local home="$1" u="$2"
    section "VERIFY - $u"
    local found=0 d hits
    for d in "$home/Library/Group Containers/UBF8T346G9.com.microsoft.oneauth" \
             "$home/Library/Group Containers/UBF8T346G9.Office/Identity" \
             "$home/Library/Application Support/OneDrive/settings" ; do
        [ -d "$d" ] || continue
        hits=$(grep -rail -- "$(printf '%s' "$TARGET_DOMAINS" | awk '{print $1}')" "$d" 2>/dev/null | head -10)
        if [ -n "$hits" ]; then
            printf '%s\n' "$hits" | while IFS= read -r h; do [ -n "$h" ] && log WARN "   STILL PRESENT: $h"; done
            found=1
        fi
    done
    if [ "$found" = "1" ]; then
        TARGET_STILL_PRESENT=$((TARGET_STILL_PRESENT + 1))
        log WARN "Old-tenant material still on disk for $u - see the lines above."
    else
        log OK "No file under the inspected stores names the old tenant for $u."
    fi
    return 0
}

# ============================================================================================
#  SUMMARY AND RECEIPT
# ============================================================================================
write_summary() {
    local dur=$(( $(date +%s) - START_EPOCH ))
    section "SUMMARY"
    log INFO "Computer            : $HOSTNAME_SHORT"
    log INFO "Modules run         :$SELECTED"
    log INFO "Mode                : $([ "$DRY_RUN" = "1" ] && echo 'DRY RUN - nothing changed' || echo 'LIVE')"
    log INFO "Target domain       : $TARGET_DOMAINS"
    log INFO "Profiles processed  : $PROCESSED_USERS"
    log INFO "Items removed       : $ITEMS_REMOVED"
    log INFO "Items kept          : $ITEMS_KEPT   (other tenants, other users)"
    log INFO "Space reclaimed     : $(fmt_bytes "$BYTES_FREED")"
    log INFO "Warnings            : $WARN_COUNT"
    log INFO "Errors              : $ERROR_COUNT"
    log INFO "Still present       : $TARGET_STILL_PRESENT profile(s) with old-tenant material"
    log INFO "Restart recommended : $([ "$RESTART_RECOMMENDED" = "1" ] && echo 'YES - some items were locked' || echo 'No')"
    log INFO "Duration            : ${dur}s"
    log INFO "Log                 : ${LOG_FILE:-'(console only)'}"
    log INFO "Actions             : ${ACTIONS_FILE:-'(none)'}"
    [ -d "$LOG_DIR/backup-$HOSTNAME_SHORT-$STAMP" ] && log INFO "Backups             : $LOG_DIR/backup-$HOSTNAME_SHORT-$STAMP"

    if [ -n "$RECEIPT_FILE" ]; then
        {
            printf '{\n'
            printf '  "version": "%s",\n'          "$SCRIPT_VERSION"
            printf '  "computer": "%s",\n'         "$HOSTNAME_SHORT"
            printf '  "modules": "%s",\n'          "$(printf '%s' "$SELECTED" | sed 's/^ *//')"
            printf '  "targetDomain": "%s",\n'     "$TARGET_DOMAINS"
            printf '  "oldTenantId": "%s",\n'      "$OLD_TENANT_ID"
            printf '  "dryRun": %s,\n'             "$([ "$DRY_RUN" = "1" ] && echo true || echo false)"
            printf '  "profilesHandled": %s,\n'    "$PROCESSED_USERS"
            printf '  "itemsRemoved": %s,\n'       "$ITEMS_REMOVED"
            printf '  "itemsKept": %s,\n'          "$ITEMS_KEPT"
            printf '  "bytesFreed": %s,\n'         "$BYTES_FREED"
            printf '  "warnings": %s,\n'           "$WARN_COUNT"
            printf '  "errors": %s,\n'             "$ERROR_COUNT"
            printf '  "stillPresent": %s,\n'       "$TARGET_STILL_PRESENT"
            printf '  "restartRecommended": %s,\n' "$([ "$RESTART_RECOMMENDED" = "1" ] && echo true || echo false)"
            printf '  "completedUtc": "%s"\n'      "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            printf '}\n'
        } > "$RECEIPT_FILE" 2>/dev/null && log INFO "Receipt             : $RECEIPT_FILE"
    fi
    return 0
}

# ================================================ MAIN ======================================
init_logging
log STEP "=============================================================================="
log STEP "  POST-MIGRATION CLEANUP FOR macOS  v$SCRIPT_VERSION"
log STEP "=============================================================================="

if [ "$(id -u)" != "0" ]; then
    log ERROR "Must run as root (RMM/agent context). Re-run with sudo."
    exit 2
fi
# $HOME is /var/root under an RMM. Everything below resolves homes from Directory Services.
log INFO "macOS version   : $(sw_vers -productVersion 2>/dev/null || echo unknown)"
log INFO "Running as      : $(id -un) (uid $(id -u))"
log INFO "Target domain   : $TARGET_DOMAINS"
log INFO "Old tenant      : $OLD_TENANT_ID"
log INFO "New tenant      : $NEW_TENANT_ID   (never removed)"
log INFO "Mode            : $([ "$DRY_RUN" = "1" ] && echo 'DRY RUN - nothing will change' || echo 'LIVE')"
log INFO ""
log STEP "Modules selected:"
for m in $MODULE_NAMES; do
    has_module "$m" || continue
    case "$(module_scope "$m")" in
        AllAccounts|SignsOut) log WARN "   $(printf '%-18s' "$m") [$(module_scope "$m")]  $(module_desc "$m")" ;;
        *)                    log INFO "   $(printf '%-18s' "$m") [$(module_scope "$m")]  $(module_desc "$m")" ;;
    esac
done
NOTRUN=""
for m in $MODULE_NAMES; do has_module "$m" || NOTRUN="$NOTRUN $m"; done
[ -n "$(printf '%s' "$NOTRUN" | tr -d ' ')" ] && log KEEP "Not running:$NOTRUN"

if command -v caffeinate >/dev/null 2>&1 && [ "$DRY_RUN" != "1" ]; then
    caffeinate -dimsu -w $$ &
fi

get_console_user
if [ -n "$CONSOLE_USER" ]; then
    log INFO "Console user    : $CONSOLE_USER (uid $CONSOLE_UID)"
else
    log WARN "Nobody is signed in at the GUI. File-level work will run, but the login keychain,"
    log WARN "the SSO extension and the work-account records need an unlocked session - those"
    log WARN "steps will be skipped. Re-run once the user has signed in."
fi

if [ "$CONSOLE_ONLY" = "1" ]; then TARGET_USERS="$CONSOLE_USER"; else TARGET_USERS=$(list_local_users); fi
TARGET_USERS=$(printf '%s\n' "$TARGET_USERS" | awk 'NF' | sort -u)
if [ -z "$TARGET_USERS" ]; then
    log ERROR "No eligible user account found. Nothing to do."
    write_summary; exit 3
fi
log INFO "Target users    : $(printf '%s' "$TARGET_USERS" | tr '\n' ' ')"

report_mdm_state
quit_apps

while IFS= read -r U; do
    [ -n "$U" ] || continue
    HOMEDIR=$(user_home "$U")
    if [ -z "$HOMEDIR" ] || [ ! -d "$HOMEDIR" ]; then
        log WARN "User $U has no resolvable home directory - skipped."; continue
    fi
    case "$HOMEDIR" in
        /Users/*) : ;;
        *) if [ "${PMC_ALLOW_NONSTANDARD_HOME:-0}" != "1" ]; then
               log WARN "User $U home '$HOMEDIR' is outside /Users - skipped for safety."; continue
           fi ;;
    esac
    UID_N=$(id -u "$U" 2>/dev/null || echo "")
    IS_CONSOLE=0
    [ -n "$CONSOLE_USER" ] && [ "$U" = "$CONSOLE_USER" ] && [ -n "$UID_N" ] && IS_CONSOLE=1

    log STEP "##############################################################################"
    log STEP "  PROFILE: $U     home: $HOMEDIR     signed in: $([ "$IS_CONSOLE" = "1" ] && echo yes || echo no)"
    log STEP "##############################################################################"

    # File-level modules work for any profile.
    has_module DeltaTokens    && mod_delta_tokens    "$HOMEDIR" "$U"
    has_module DeltaOffice    && mod_delta_office    "$HOMEDIR" "$U" "$([ "$IS_CONSOLE" = "1" ] && echo "$UID_N" || echo "")"
    has_module DeltaOneDrive  && mod_delta_onedrive  "$HOMEDIR" "$U"
    has_module DeltaBrowser   && mod_delta_browser   "$HOMEDIR" "$U"
    has_module AppCache       && mod_app_cache       "$HOMEDIR" "$U"
    has_module OutlookCache   && mod_outlook_cache   "$HOMEDIR" "$U"
    has_module BrowserAll     && mod_browser_all     "$HOMEDIR" "$U"
    has_module OneDriveAll    && mod_onedrive_all    "$HOMEDIR" "$U"
    has_module OutlookProfileAll && mod_outlook_profile_all "$HOMEDIR" "$U"
    has_module CompanyPortalAll  && mod_company_portal_all  "$HOMEDIR" "$U"

    # Session-bound modules: only possible inside the signed-in user's own session, because
    # the login keychain and the SSO extension are per-user and session-bound.
    if [ "$IS_CONSOLE" = "1" ]; then
        has_module DeltaKeychain    && mod_delta_keychain    "$U" "$UID_N" "$HOMEDIR"
        has_module DeltaSSO         && mod_delta_sso         "$U" "$UID_N"
        has_module DeltaWorkAccount && mod_delta_workaccount "$U" "$UID_N" "$HOMEDIR"
        has_module KeychainAll      && mod_keychain_all      "$U" "$UID_N" "$HOMEDIR"
        has_module TokenStoreAll    && mod_token_store_all   "$U" "$UID_N" "$HOMEDIR"
    else
        if has_module DeltaKeychain || has_module DeltaSSO || has_module DeltaWorkAccount \
        || has_module KeychainAll   || has_module TokenStoreAll; then
            log INFO "$U is not the signed-in user - keychain, SSO and work-account steps deferred."
            log INFO "Run this again while $U is signed in to finish those."
        fi
    fi

    verify_user "$HOMEDIR" "$U"
    PROCESSED_USERS=$((PROCESSED_USERS + 1))
done <<EOF_USERS
$TARGET_USERS
EOF_USERS

if [ "$RESTART_RECOMMENDED" = "1" ]; then
    log WARN "*** RESTART RECOMMENDED: some items were locked by running processes. ***"
fi
write_summary

if [ "$DRY_RUN" = "1" ]; then
    log DRY "DRY RUN - nothing on this Mac was changed."
else
    log STEP "Sign out and back in (or restart) before checking an app's account list - those"
    log STEP "pickers cache, so a stale entry there is not a failed removal."
fi

EXIT_CODE=0
if   [ "$TARGET_STILL_PRESENT" -gt 0 ]; then EXIT_CODE=5
elif [ "$ERROR_COUNT" -gt 0 ];          then EXIT_CODE=2
elif [ "$WARN_COUNT"  -gt 0 ];          then EXIT_CODE=1
fi
log INFO "Exit code $EXIT_CODE"
exit $EXIT_CODE
