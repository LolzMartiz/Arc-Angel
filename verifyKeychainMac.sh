#!/bin/bash
# =============================================================================================
#  verifyKeychainMac.sh                                                                v1.0.0
#
#  The v3.1.0 cleanup prints:
#
#      [OK] Purged OneAuth account/token store - account pickers will be empty.
#
#  That line is NOT evidence. It is printed whenever the sqlite command exits 0 - and
#  "DELETE FROM genp WHERE agrp='...'" exits 0 even when it matches ZERO rows. So the
#  message appears whether it purged 40 accounts or none at all.
#
#  This script replaces that guess with a number: how many broker account rows exist
#  before, whether they can actually be deleted, and how many exist after.
#
#  Run as the affected user. sudo only where it asks.
#
#      chmod +x verifyKeychainMac.sh && ./verifyKeychainMac.sh          # report only
#      chmod +x verifyKeychainMac.sh && ./verifyKeychainMac.sh --fix    # report + clear
# =============================================================================================

FIX=0
[ "${1:-}" = "--fix" ] && FIX=1

if [ "$(id -u)" = "0" ]; then
    echo "Run as the USER, not root - the keychain is per-user and \$HOME would be /var/root." >&2
    exit 2
fi

AGRP='UBF8T346G9.com.microsoft.identity.universalstorage'
LOGIN_KC="$HOME/Library/Keychains/login.keychain-db"

echo "================================================================================"
echo "  KEYCHAIN / BROKER VERIFICATION      user: $(whoami)      $(sw_vers -productVersion 2>/dev/null)"
echo "================================================================================"
echo "mode : $([ $FIX = 1 ] && echo 'REPORT + FIX' || echo 'REPORT ONLY')"
echo ""

# ---------------------------------------------------------------------------- 1. login keychain
echo "--- 1. What Microsoft items are actually IN the login keychain? ---"
if [ ! -f "$LOGIN_KC" ]; then
    echo "  login.keychain-db not found at $LOGIN_KC"
else
    security list-keychains -s "$LOGIN_KC" >/dev/null 2>&1
    DUMP=$(security dump-keychain "$LOGIN_KC" 2>/dev/null)
    if [ -z "$DUMP" ]; then
        echo "  Could not read the keychain."
        echo "  >>> Terminal probably lacks Full Disk Access."
        echo "      System Settings > Privacy & Security > Full Disk Access > add Terminal,"
        echo "      quit Terminal completely, reopen, and run this again."
    else
        echo "$DUMP" | grep -o '"svce"<blob>="[^"]*"' | sed 's/"svce"<blob>="//; s/"$//' \
          | grep -i -e microsoft -e adal -e oneauth -e office -e teams -e msal -e workplacejoin -e enterprise \
          | sort | uniq -c | sort -rn | sed 's/^/   service: /'
        echo "$DUMP" | grep -o '"labl"<blob>="[^"]*"' | sed 's/"labl"<blob>="//; s/"$//' \
          | grep -i -e microsoft -e adal -e oneauth -e office -e teams -e msal -e workplacejoin -e enterprise \
          | sort | uniq -c | sort -rn | sed 's/^/   label  : /'
        echo "   (nothing listed above = the login keychain is already clean)"
    fi
fi
echo ""

# ---------------------------------------------------------------------------- 2. broker store
echo "--- 2. The broker account store (this is what fills the account picker) ---"
KC2=$(find "$HOME/Library/Keychains" -maxdepth 2 -name 'keychain-2.db' 2>/dev/null | head -1)
if [ -z "$KC2" ]; then
    echo "  keychain-2.db not found under ~/Library/Keychains"
    echo "  On recent macOS it may live under a UUID subfolder; searched maxdepth 2."
else
    echo "  file : $KC2"
    if ! command -v sqlite3 >/dev/null 2>&1; then
        echo "  sqlite3 not available - cannot inspect."
    else
        BEFORE=$(sqlite3 "$KC2" "SELECT COUNT(*) FROM genp WHERE agrp='$AGRP';" 2>&1)
        case "$BEFORE" in
            ''|*[!0-9]*)
                echo "  CANNOT READ IT: $BEFORE"
                echo ""
                echo "  >>> THIS IS THE LIKELY ANSWER."
                echo "      If sqlite3 cannot read this file, the v3 script could not write to it"
                echo "      either - yet it still printed 'account pickers will be empty', because"
                echo "      it never checked. Grant Terminal Full Disk Access and re-run."
                ;;
            *)
                echo "  broker account rows BEFORE : $BEFORE"
                if [ "$BEFORE" = "0" ]; then
                    echo "  -> the store is already empty. The account picker is being filled from"
                    echo "     somewhere else (app container, or the Enterprise SSO plug-in)."
                elif [ $FIX = 1 ]; then
                    echo "  quitting Microsoft apps first..."
                    osascript -e 'quit app "Microsoft Teams"' -e 'quit app "Microsoft Outlook"' >/dev/null 2>&1
                    sleep 3
                    pkill -9 -f 'MSTeams|Microsoft Teams|Microsoft Outlook|com.microsoft' >/dev/null 2>&1
                    sleep 1
                    DEL=$(sqlite3 "$KC2" "DELETE FROM genp WHERE agrp='$AGRP'; SELECT changes();" 2>&1)
                    echo "  rows actually deleted      : $DEL"
                    AFTER=$(sqlite3 "$KC2" "SELECT COUNT(*) FROM genp WHERE agrp='$AGRP';" 2>&1)
                    echo "  broker account rows AFTER  : $AFTER"
                    if [ "$AFTER" != "0" ]; then
                        echo "  >>> Rows survived the delete. securityd holds this file open and rewrites"
                        echo "      it. Log the user out and back in (or reboot), then re-run --fix."
                    fi
                else
                    echo "  -> re-run with --fix to clear these $BEFORE row(s)."
                fi
                ;;
        esac
    fi
fi
echo ""

# ---------------------------------------------------------------------------- 3. SSO plug-in
echo "--- 3. Microsoft Enterprise SSO plug-in (a second, separate account source) ---"
if command -v app-sso >/dev/null 2>&1; then
    app-sso -l 2>/dev/null | sed 's/^/   /'
    echo "   (entries above are held by the SSO extension, not by Teams)"
else
    echo "   app-sso not present."
fi
PROF=$(profiles show -type configuration 2>/dev/null | grep -i -c 'extensible.sso\|com.microsoft.CompanyPortalMac.ssoextension' 2>/dev/null)
echo "   SSO configuration profiles matching Microsoft: ${PROF:-0}"
echo ""

# ---------------------------------------------------------------------------- 4. leftovers
echo "--- 4. Group containers still on disk ---"
for P in \
    "$HOME/Library/Group Containers/UBF8T346G9.Office" \
    "$HOME/Library/Group Containers/UBF8T346G9.com.microsoft.teams" \
    "$HOME/Library/Group Containers/UBF8T346G9.com.microsoft.oneauth" \
    "$HOME/Library/Containers/com.microsoft.teams2"
do
    if [ -e "$P" ]; then echo "   present : $P"; else echo "   absent  : $P"; fi
done
echo ""
echo "   NOTE: UBF8T346G9.Office must stay - the mailbox lives inside it at"
echo "         UBF8T346G9.Office/Outlook. Never delete the whole group container."
echo ""

echo "================================================================================"
echo "  Section 2 is the one that matters. A number, not a message."
echo "================================================================================"
