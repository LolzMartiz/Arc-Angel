#!/bin/bash
set -e
PRODUCT_FILE="/usr/share/code/resources/app/product.json"
BACKUP_FILE="${PRODUCT_FILE}.bak"

[[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }
[[ -f "$PRODUCT_FILE" ]] || { echo "VS Code not installed at expected path."; exit 1; }

[[ -f "$BACKUP_FILE" ]] || cp "$PRODUCT_FILE" "$BACKUP_FILE"

python3 - <<EOF
import json
with open("$PRODUCT_FILE") as f: data = json.load(f)
data.pop("extensionsGallery", None)
with open("$PRODUCT_FILE", "w") as f: json.dump(data, f, indent=4)
print("Marketplace disabled.")
EOF

echo "Done. Fully quit VS Code (close all windows + tray) before reopening."
