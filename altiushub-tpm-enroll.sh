#!/bin/bash
###############################################################################
# AltiusHub LUKS TPM2 Enrollment — runs via cron, no TTY required
# Target: Ubuntu/Debian with LUKS2 root + TPM 2.0
# Behavior: enrolls TPM, updates crypttab, rebuilds initramfs, self-disables
###############################################################################

LOG=/var/log/altiushub-tpm-enroll.log
LOCK=/var/lib/altiushub-tpm-enrolled.flag
exec >>"$LOG" 2>&1

echo "==== $(date '+%F %T') TPM enrollment run ===="

# Self-disable if already enrolled — cron will hit this repeatedly otherwise
if [[ -f "$LOCK" ]]; then
  echo "Already enrolled (lock file present). Exiting."
  exit 0
fi

# ----- CONFIG: edit these two lines before pushing to GitHub ---------------
LUKS_DEV="/dev/nvme0n1p3"
LUKS_PASSPHRASE='REPLACE_WITH_REAL_INSTALL_PASSPHRASE'
# ---------------------------------------------------------------------------

# Sanity: device must be LUKS
if ! cryptsetup isLuks "$LUKS_DEV"; then
  echo "ERROR: $LUKS_DEV is not a LUKS device. Aborting."
  exit 1
fi

# Sanity: TPM 2.0 must be present
if [[ ! -e /sys/class/tpm/tpm0/tpm_version_major ]]; then
  echo "ERROR: no TPM device found. Aborting."
  exit 1
fi
TPM_VER=$(cat /sys/class/tpm/tpm0/tpm_version_major)
if [[ "$TPM_VER" != "2" ]]; then
  echo "ERROR: TPM is version $TPM_VER, need 2. Aborting."
  exit 1
fi
echo "TPM 2.0 detected."

# Install required packages
DEBIAN_FRONTEND=noninteractive apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y systemd-cryptsetup tpm2-tools

# Verify install passphrase works BEFORE making changes
EK=/tmp/.altiushub_ek
printf '%s' "$LUKS_PASSPHRASE" > "$EK"
chmod 600 "$EK"

if ! cryptsetup luksOpen --test-passphrase "$LUKS_DEV" --key-file="$EK" </dev/null; then
  echo "ERROR: install passphrase is wrong. Aborting before any changes."
  shred -u "$EK"
  exit 1
fi
echo "Install passphrase verified."

# Skip if TPM keyslot already exists (idempotent)
if cryptsetup luksDump "$LUKS_DEV" | grep -q "systemd-tpm2"; then
  echo "TPM2 keyslot already exists. Marking enrolled."
  touch "$LOCK"
  shred -u "$EK"
  exit 0
fi

# Enroll TPM2 — PCR 7 binds to Secure Boot state
PASSWORD=$(cat "$EK") systemd-cryptenroll \
  --tpm2-device=auto \
  --tpm2-pcrs=7 \
  "$LUKS_DEV" </dev/null
ENROLL_EXIT=$?
shred -u "$EK"

if [[ $ENROLL_EXIT -ne 0 ]]; then
  echo "ERROR: systemd-cryptenroll failed (exit $ENROLL_EXIT). Aborting."
  exit 1
fi
echo "TPM2 enrolled successfully."

# Update /etc/crypttab so initramfs uses TPM at boot
LUKS_UUID=$(cryptsetup luksUUID "$LUKS_DEV")
if grep -q "$LUKS_UUID" /etc/crypttab; then
  if ! grep "$LUKS_UUID" /etc/crypttab | grep -q "tpm2-device"; then
    cp /etc/crypttab /etc/crypttab.bak.altiushub
    sed -i "/$LUKS_UUID/ s|luks|luks,tpm2-device=auto|" /etc/crypttab
    echo "crypttab updated."
  else
    echo "crypttab already has tpm2-device=auto."
  fi
else
  echo "WARNING: UUID $LUKS_UUID not in /etc/crypttab. Manual fix may be needed."
fi

# Rebuild initramfs so the new crypttab option takes effect
update-initramfs -u -k all
echo "initramfs rebuilt."

# Verify and mark enrolled
cryptsetup luksDump "$LUKS_DEV" | grep -E "Keyslot|systemd-tpm2" | head -20
touch "$LOCK"

echo "==== Enrollment complete. Reboot device to test silent boot. ===="
echo "If passphrase prompt still appears after reboot, TPM unlock failed —"
echo "type the install passphrase as fallback (it still works)."

# Remove the cron entry so this never runs again
sed -i '/altiushub-tpm-enroll/d' /etc/crontab 2>/dev/null
crontab -l 2>/dev/null | grep -v 'altiushub-tpm-enroll' | crontab -

exit 0
