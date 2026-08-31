#!/bin/bash
# =============================================================================================
#  clearTeamsIdentityMac.sh                                                             v1.0.0
#
#  Clears Teams + the shared Microsoft identity broker for ONE user on macOS.
#  Fixes AADSTS50020 (Teams asking for a token in the old tenant) and clears the
#  "Scegli un account per continuare" account picker.
#
#  MUST run as the actual user - NOT with su, NOT with sudo.
#  The script refuses to run as root, because as root $HOME is /var/root and every
#  path below would silently point at the wrong (empty) home directory. That is
#  exactly what happened on the first attempt: the commands "succeeded" and did nothing.
#
#      chmod +x clearTeamsIdentityMac.sh
#      ./clearTeamsIdentityMac.sh
#
#  ############################################################################
#  #  NEVER DELETED BY THIS SCRIPT - the mailbox, incl. "On My Computer":     #
#  #    ~/Library/Group Containers/UBF8T346G9.Office/Outlook/                 #
#  ############################################################################
# =============================================================================================

# ---------------------------------------------------------------------------- root guard
if [ "$(id -u)" = "0" ]; then
    echo ""
    echo "REFUSING TO RUN AS ROOT."
    echo ""
    echo "  You are root (\$HOME = $HOME). Every path here is under the user's home"
    echo "  directory, and the keychain is per-user. As root this script would delete"
    echo "  nothing, clear nothing, and report success."
    echo ""
    echo "  Type  exit  to leave the root shell, confirm the prompt ends in \$ not #,"
    echo "  then run this again as alessandrom."
    echo ""
    exit 2
fi
if [ -n "${SUDO_USER:-}" ]; then
    echo "REFUSING: started via sudo. Run it directly as the user, with no sudo." >&2
    exit 2
fi

ME="$(whoami)"
echo "============================================================================"
echo "  CLEAR TEAMS + MICROSOFT IDENTITY   (user: $ME)"
echo "============================================================================"
echo "HOME    : $HOME"
echo "whoami  : $ME"
if [ "$HOME" != "/Users/$ME" ]; then
    echo ""
    echo "WARNING: \$HOME is not /Users/$ME. Check you are the right user before continuing."
    echo ""
fi
echo ""

OLD_TENANT_ID='905cd5ac-a071-4697-a446-c9077a81e24b'
OLD_TENANT_DOMAIN='mainettigroup.onmicrosoft.com'

# ---------------------------------------------------------------------------- 1. before
echo "--- 1. BEFORE: files still naming the old tenant ---"
grep -rIl -e "$OLD_TENANT_ID" -e "$OLD_TENANT_DOMAIN" \
    "$HOME/Library/Group Containers/UBF8T346G9.Office" \
    "$HOME/Library/Containers/com.microsoft.teams2" \
    "$HOME/Library/Application Support/Microsoft" \
    "$HOME/Library/Group Containers/UBF8T346G9.com.microsoft.teams" \
    2>/dev/null | grep -v '/Outlook/' | head -40
echo "(nothing above = no file holds it; the account list is then keychain-only)"
echo ""

echo "--- keychain entries that feed the account picker, BEFORE ---"
security dump-keychain 2>/dev/null | grep -i -o '"svce"<blob>="[^"]*"' | sort -u | grep -i -e microsoft -e adal -e oneauth -e workplacejoin -e enterpriseregistration | head -30
echo ""

# ---------------------------------------------------------------------------- 2. quit apps
echo "--- 2. quitting apps ---"
osascript -e 'quit app "Microsoft Teams"' -e 'quit app "Microsoft Outlook"' >/dev/null 2>&1
sleep 3
pkill -9 -f 'MSTeams|Microsoft Teams|Microsoft Outlook|com.microsoft.teams' >/dev/null 2>&1
echo "done"
echo ""

# ---------------------------------------------------------------------------- 3. Teams
echo "--- 3. removing Teams local state (nothing user-owned lives here) ---"
for P in \
    "$HOME/Library/Containers/com.microsoft.teams2" \
    "$HOME/Library/Containers/com.microsoft.teams" \
    "$HOME/Library/Group Containers/UBF8T346G9.com.microsoft.teams" \
    "$HOME/Library/Application Support/Microsoft/Teams" \
    "$HOME/Library/Caches/com.microsoft.teams2" \
    "$HOME/Library/Caches/com.microsoft.teams" \
    "$HOME/Library/Preferences/com.microsoft.teams2.plist" \
    "$HOME/Library/Preferences/com.microsoft.teams.plist" \
    "$HOME/Library/Saved Application State/com.microsoft.teams2.savedState" \
    "$HOME/Library/Saved Application State/com.microsoft.teams.savedState" \
    "$HOME/Library/WebKit/com.microsoft.teams2" \
    "$HOME/Library/HTTPStorages/com.microsoft.teams2" \
    "$HOME/Library/HTTPStorages/com.microsoft.teams2.binarycookies"
do
    if [ -e "$P" ]; then rm -rf "$P" && echo "  removed  $P"; fi
done
echo ""

# ---------------------------------------------------------------------------- 4. shared identity
echo "--- 4. removing the SHARED Microsoft identity broker stores ---"
echo "    (this is what the account picker reads - the step the first attempt missed)"
for P in \
    "$HOME/Library/Group Containers/UBF8T346G9.com.microsoft.identity.universalstorage" \
    "$HOME/Library/Group Containers/UBF8T346G9.Office/OneAuth" \
    "$HOME/Library/Group Containers/UBF8T346G9.Office/MicrosoftIdentityCache" \
    "$HOME/Library/Application Support/Microsoft/OneAuth" \
    "$HOME/Library/Caches/com.microsoft.OneAuth" \
    "$HOME/Library/Caches/com.microsoft.Outlook" \
    "$HOME/Library/Containers/com.microsoft.Outlook/Data/Library/Caches"
do
    if [ -e "$P" ]; then rm -rf "$P" && echo "  removed  $P"; fi
done
echo ""

# ---------------------------------------------------------------------------- 5. keychain
echo "--- 5. keychain (per-user - this is why root did nothing) ---"
removed=0
for L in \
    "Microsoft Office Identities Cache 3" \
    "Microsoft Office Identities Settings 3" \
    "Microsoft Office Ticket Cache" \
    "Microsoft Credentials" \
    "MicrosoftOfficeRMSCredential" \
    "com.microsoft.adalcache" \
    "MSOpenTech.ADAL.1" \
    "OneAuthAccount" \
    "Microsoft Teams Identities Cache" \
    "MSTeams" \
    "com.microsoft.workplacejoin.registeredDeviceCredential" \
    "com.microsoft.workplacejoin.deviceCertificate"
do
    n=0
    while [ $n -lt 40 ] && security delete-generic-password -l "$L" >/dev/null 2>&1; do
        n=$((n+1)); removed=$((removed+1))
    done
    [ $n -gt 0 ] && echo "  removed $n entry(ies) labelled: $L"
done
for S in "enterpriseregistration.windows.net" "login.microsoftonline.com" "login.windows.net"; do
    n=0
    while [ $n -lt 40 ] && security delete-internet-password -s "$S" >/dev/null 2>&1; do
        n=$((n+1)); removed=$((removed+1))
    done
    [ $n -gt 0 ] && echo "  removed $n internet entry(ies) for: $S"
done
echo "  total keychain entries removed: $removed"
echo ""

# ---------------------------------------------------------------------------- 6. verify
echo "--- 6. AFTER: anything left naming the old tenant? ---"
LEFT=$(grep -rIl -e "$OLD_TENANT_ID" -e "$OLD_TENANT_DOMAIN" \
    "$HOME/Library/Group Containers/UBF8T346G9.Office" \
    "$HOME/Library/Containers/com.microsoft.teams2" \
    "$HOME/Library/Application Support/Microsoft" \
    "$HOME/Library/Group Containers/UBF8T346G9.com.microsoft.teams" \
    2>/dev/null | grep -v '/Outlook/' | head -20)
if [ -z "$LEFT" ]; then echo "  clean"; else echo "$LEFT"; fi
echo ""

echo "--- mailbox intact? ---"
if [ -d "$HOME/Library/Group Containers/UBF8T346G9.Office/Outlook" ]; then
    echo "  PRESENT: $HOME/Library/Group Containers/UBF8T346G9.Office/Outlook"
    du -sh "$HOME/Library/Group Containers/UBF8T346G9.Office/Outlook" 2>/dev/null | sed 's/^/  size: /'
else
    echo "  (Outlook profile folder not present - Outlook may never have been set up here)"
fi
echo ""

echo "============================================================================"
echo "  NEXT"
echo "============================================================================"
echo "  1. Reopen Teams:  open -a \"Microsoft Teams\""
echo "  2. The account picker should now be EMPTY. Sign in fresh as"
echo "     Alessandro.Marchi@mainetti.com"
echo "  3. If a picker still lists reca11@recagroupspa.onmicrosoft.com or any other"
echo "     organisation, those entries are in the login keychain under a name this"
echo "     script did not match. Open Keychain Access (or Passwords in newer macOS),"
echo "     search 'microsoft', and delete every result, then repeat step 1."
echo "============================================================================"
