#!/usr/bin/env bash
#
# block-extensions.sh
# Blocks installation of ALL extensions in Google Chrome and Microsoft Edge
# on Linux via enterprise managed policy.
#
# Run as root (you said you're connecting in at root level, so this is fine):
#   sudo bash block-extensions.sh
#
# Reverse it any time with:
#   sudo bash block-extensions.sh --unblock

set -euo pipefail

CHROME_DIR="/etc/opt/chrome/policies/managed"
EDGE_DIR="/etc/opt/edge/policies/managed"
POLICY_FILE="block_extensions.json"

if [[ $EUID -ne 0 ]]; then
  echo "Run this as root (sudo)." >&2
  exit 1
fi

# --- Unblock mode -----------------------------------------------------------
if [[ "${1:-}" == "--unblock" ]]; then
  rm -f "$CHROME_DIR/$POLICY_FILE" "$EDGE_DIR/$POLICY_FILE"
  echo "Removed extension-block policy from Chrome and Edge."
  echo "Restart the browsers (or reload policies) to lift the block."
  exit 0
fi

# --- Block mode -------------------------------------------------------------
# ExtensionInstallBlocklist with "*" blocks every extension the user tries to
# add and disables any already installed by the user. Force-installed
# extensions (ExtensionInstallForcelist) are exempt and still install — which
# is what lets you push approved extensions while users stay locked out.
write_policy() {
  local dir="$1" name="$2"
  mkdir -p "$dir"
  cat > "$dir/$POLICY_FILE" <<'EOF'
{
  "ExtensionInstallBlocklist": ["*"]
}
EOF
  chmod 644 "$dir/$POLICY_FILE"
  echo "$name blocked  ->  $dir/$POLICY_FILE"
}

write_policy "$CHROME_DIR" "Chrome"
write_policy "$EDGE_DIR"   "Edge"

echo
echo "Done. Restart Chrome and Edge for the policy to load."
echo "Verify at chrome://policy and edge://policy (look for ExtensionInstallBlocklist = *)."
