#!/usr/bin/env bash
# altiushub-fix-launcher.sh
# Single-shot remediation for known AltiusHub fleet issues identified by
# altiushub-verify-access.sh. Idempotent: only fixes what's wrong, skips
# anything already correct. Run as root.
#
# Usage (curl-pipe form):
#   curl -fsSL https://raw.githubusercontent.com/LolzMartiz/Arc-Angel/refs/heads/main/altiushub-fix-launcher.sh | sudo bash
#
# Or with a specific target user (defaults to UID 1000):
#   curl -fsSL https://raw.githubusercontent.com/LolzMartiz/Arc-Angel/refs/heads/main/altiushub-fix-launcher.sh | sudo bash -s likhitha

set -u
[[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }

LOG_FILE="/var/log/altiushub-fix-launcher.log"
mkdir -p "$(dirname "$LOG_FILE")"
: > "$LOG_FILE"

TARGET_USER="${1:-$(awk -F: '$3==1000 {print $1; exit}' /etc/passwd)}"
id "$TARGET_USER" >/dev/null 2>&1 || { echo "User '$TARGET_USER' not found."; exit 1; }

# ANSI colours for live output; log file gets plain text
C_OK="\033[32m"; C_FIX="\033[33m"; C_SKIP="\033[90m"; C_FAIL="\033[31m"; C_OFF="\033[0m"

# Per-module counters
FIXED=0; SKIPPED=0; FAILED=0

log()  { printf '%s\n'   "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
ok()   { printf "  ${C_OK}[OK]${C_OFF}    %s\n"   "$1"; printf '  [OK]    %s\n'   "$1" >>"$LOG_FILE"; SKIPPED=$((SKIPPED+1)); }
fix()  { printf "  ${C_FIX}[FIX]${C_OFF}   %s\n"  "$1"; printf '  [FIX]   %s\n'  "$1" >>"$LOG_FILE"; FIXED=$((FIXED+1)); }
skip() { printf "  ${C_SKIP}[SKIP]${C_OFF}  %s\n" "$1"; printf '  [SKIP]  %s\n' "$1" >>"$LOG_FILE"; SKIPPED=$((SKIPPED+1)); }
fail() { printf "  ${C_FAIL}[FAIL]${C_OFF}  %s\n" "$1"; printf '  [FAIL]  %s\n' "$1" >>"$LOG_FILE"; FAILED=$((FAILED+1)); }
hdr()  { printf "\n=================================================================\n  %s\n=================================================================\n" "$1" | tee -a "$LOG_FILE"; }

log "================================================================="
log "  ALTIUSHUB FLEET REMEDIATION"
log "================================================================="
log "Host:        $(hostname)"
log "Target user: $TARGET_USER (uid=$(id -u "$TARGET_USER"))"
log "Log file:    $LOG_FILE"

###############################################################################
hdr "1. pgAdmin4 — launcher .desktop entry"
###############################################################################
if ! dpkg -s pgadmin4-desktop >/dev/null 2>&1; then
  skip "pgadmin4-desktop not installed — nothing to do"
else
  # Locate the real binary (NOT the AppArmor profile in /etc/)
  pg_bin=""
  for cand in \
      /usr/pgadmin4/bin/pgadmin4 \
      /usr/share/pgadmin4-desktop/pgadmin4 \
      /usr/bin/pgadmin4 \
      /opt/pgadmin4/bin/pgadmin4; do
    [[ -x "$cand" && ! -d "$cand" ]] && { pg_bin="$cand"; break; }
  done
  if [[ -z "$pg_bin" ]]; then
    while IFS= read -r f; do
      [[ -f "$f" && -x "$f" && "$f" != /etc/* ]] && { pg_bin="$f"; break; }
    done < <(dpkg -L pgadmin4-desktop 2>/dev/null | grep -E 'pgadmin4(-desktop)?$')
  fi

  if [[ -z "$pg_bin" || ! -x "$pg_bin" ]]; then
    fail "could not locate pgadmin4 binary — package may be broken"
    log  "  dpkg -L output (binary candidates):"
    dpkg -L pgadmin4-desktop 2>/dev/null | grep -E 'bin/|pgadmin4$' | sed 's/^/    /' | tee -a "$LOG_FILE"
  else
    pg_icon="$(dpkg -L pgadmin4-desktop 2>/dev/null | grep -E 'pgadmin4\.(png|svg)$' | head -1)"
    pg_icon="${pg_icon:-/usr/share/pixmaps/pgadmin4.png}"
    target=/usr/share/applications/pgadmin4.desktop

    # Check if existing .desktop already points to the right binary
    if [[ -f "$target" ]] && grep -qx "Exec=$pg_bin" "$target"; then
      ok "$target already points to $pg_bin"
    else
      cat > "$target" <<EOF
[Desktop Entry]
Name=pgAdmin 4
GenericName=PostgreSQL Tools
Comment=Manage PostgreSQL databases
Exec=$pg_bin
Icon=$pg_icon
Type=Application
Categories=Development;Database;
Terminal=false
StartupNotify=true
StartupWMClass=pgAdmin4
EOF
      chmod 0644 "$target"
      fix "wrote $target with Exec=$pg_bin"
      update-desktop-database /usr/share/applications/ 2>/dev/null || true
    fi
  fi
fi

###############################################################################
hdr "2. Flatpak — restore executable bit"
###############################################################################
if [[ ! -x /usr/bin/flatpak ]] && [[ ! -e /usr/bin/flatpak ]]; then
  skip "flatpak not installed on this host"
elif [[ -f /usr/bin/flatpak ]]; then
  current="$(stat -c '%a %U:%G' /usr/bin/flatpak)"
  log "  Current perms on /usr/bin/flatpak: $current"
  if sudo -u "$TARGET_USER" test -x /usr/bin/flatpak; then
    ok "/usr/bin/flatpak already executable by $TARGET_USER"
  else
    chown root:root /usr/bin/flatpak
    chmod 755 /usr/bin/flatpak
    new="$(stat -c '%a %U:%G' /usr/bin/flatpak)"
    fix "/usr/bin/flatpak chown root:root chmod 755 (was $current, now $new)"
  fi
fi

###############################################################################
hdr "3. libfuse2 / libfuse2t64 — Dr. Sprinto AppImage runtime"
###############################################################################
if [[ ! -f /opt/altiushub/DrSprinto.AppImage ]]; then
  skip "Dr. Sprinto AppImage not present — libfuse2 not strictly required"
elif dpkg -l 2>/dev/null | grep -qE '^ii  +libfuse2(t64)? '; then
  ok "libfuse2 runtime already installed"
else
  log "  Installing libfuse2 runtime..."
  if DEBIAN_FRONTEND=noninteractive apt-get install -y libfuse2t64 >>"$LOG_FILE" 2>&1; then
    fix "libfuse2t64 installed — Dr. Sprinto can now launch"
  elif DEBIAN_FRONTEND=noninteractive apt-get install -y libfuse2 >>"$LOG_FILE" 2>&1; then
    fix "libfuse2 installed — Dr. Sprinto can now launch"
  else
    fail "could not install libfuse2 — see $LOG_FILE for apt errors"
  fi
fi

###############################################################################
hdr "4. Docker group membership"
###############################################################################
if ! getent group docker >/dev/null 2>&1; then
  skip "no 'docker' group — Docker Desktop install incomplete or not installed"
else
  for u in "$TARGET_USER" AltiusHub; do
    id "$u" >/dev/null 2>&1 || { log "  user '$u' does not exist — skipping"; continue; }
    if id -nG "$u" 2>/dev/null | grep -qw docker; then
      ok "$u already in 'docker' group"
    else
      if usermod -aG docker "$u" 2>>"$LOG_FILE"; then
        fix "$u added to 'docker' group (effective on next login)"
      else
        fail "could not add $u to 'docker' group"
      fi
    fi
  done
fi

###############################################################################
hdr "5. XDG_DATA_DIRS — system flatpak path for all users"
###############################################################################
target=/etc/profile.d/altiushub-flatpak.sh
expected='case ":${XDG_DATA_DIRS:-}:" in'
if [[ -f "$target" ]] && grep -qF "$expected" "$target"; then
  ok "$target already in place"
else
  cat > "$target" <<'EOF'
# AltiusHub fleet: ensure system-installed flatpaks are discoverable for all
# users (XDG_DATA_DIRS expansion for system flatpak exports).
case ":${XDG_DATA_DIRS:-}:" in
  *":/var/lib/flatpak/exports/share:"*) ;;
  *) export XDG_DATA_DIRS="/var/lib/flatpak/exports/share${XDG_DATA_DIRS:+:$XDG_DATA_DIRS}" ;;
esac
EOF
  chmod 0644 "$target"
  fix "wrote $target — system flatpaks now visible in launcher (after user re-login)"
fi

###############################################################################
hdr "6. Verify post-fix state for $TARGET_USER"
###############################################################################
verify() {
  local desc="$1" cmd="$2"
  if sudo -u "$TARGET_USER" bash -c "$cmd" >/dev/null 2>&1; then
    printf "  ${C_OK}[PASS]${C_OFF}  %s\n" "$desc"; printf '  [PASS]  %s\n' "$desc" >>"$LOG_FILE"
  else
    printf "  ${C_FAIL}[FAIL]${C_OFF}  %s\n" "$desc"; printf '  [FAIL]  %s\n' "$desc" >>"$LOG_FILE"
  fi
}
verify "flatpak runnable by $TARGET_USER"       "flatpak --version"
verify "docker runnable by $TARGET_USER"        "docker version 2>&1 | grep -q Server || docker version --format '{{.Client.Version}}'"
verify "Dr. Sprinto AppImage executable"        "test -x /opt/altiushub/DrSprinto.AppImage"
verify "pgAdmin .desktop entry present + valid" "grep -q '^Exec=' /usr/share/applications/pgadmin4.desktop && test -x \"\$(awk -F= '/^Exec=/{print \$2; exit}' /usr/share/applications/pgadmin4.desktop)\""

###############################################################################
hdr "SUMMARY"
###############################################################################
log "Fixed:   $FIXED"
log "Skipped: $SKIPPED  (already correct or N/A)"
log "Failed:  $FAILED"
log ""
log "Full log written to: $LOG_FILE"
log ""
log "IMPORTANT: $TARGET_USER must LOG OUT and LOG BACK IN for these changes"
log "to take full effect (docker group membership + XDG_DATA_DIRS env)."

[[ $FAILED -eq 0 ]] || exit 1
exit 0
