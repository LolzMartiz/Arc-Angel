#!/usr/bin/env bash
# altiushub-verify-access.sh
# Verifies that AltiusHub-deployed apps are visible / runnable for a normal
# (non-root) user. Run as root. Reports OK / FAIL / WARN per app.
#
# Usage:
#   sudo bash altiushub-verify-access.sh           # auto-detects UID 1000
#   sudo bash altiushub-verify-access.sh <user>    # test as a specific user
#   sudo bash altiushub-verify-access.sh AltiusHub # test as the admin user
#
# Curl-pipe form:
#   curl -fsSL https://raw.githubusercontent.com/LolzMartiz/Arc-Angel/refs/heads/main/altiushub-verify-access.sh | sudo bash

set -u
[[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }

TARGET_USER="${1:-$(awk -F: '$3==1000 {print $1; exit}' /etc/passwd)}"
id "$TARGET_USER" >/dev/null 2>&1 || { echo "User '$TARGET_USER' not found."; exit 1; }

C_OK="\033[32m"; C_FAIL="\033[31m"; C_WARN="\033[33m"; C_OFF="\033[0m"
ok()   { printf "  ${C_OK}[OK]${C_OFF}    %s\n" "$1"; }
fail() { printf "  ${C_FAIL}[FAIL]${C_OFF}  %s\n" "$1"; }
warn() { printf "  ${C_WARN}[WARN]${C_OFF}  %s\n" "$1"; }
hdr()  { printf "\n=================================================================\n  %s\n=================================================================\n" "$1"; }

asu() {  # "as user" runner: $1 = description, $2 = bash command
  local desc="$1" cmd="$2"
  if sudo -u "$TARGET_USER" bash -c "$cmd" >/dev/null 2>&1; then ok "$desc"; else fail "$desc"; fi
}

echo "================================================================="
echo "  ALTIUSHUB FLEET — APP ACCESSIBILITY VERIFICATION"
echo "================================================================="
echo "  Host:           $(hostname)"
echo "  Distro / arch:  $(. /etc/os-release; echo "$PRETTY_NAME") / $(dpkg --print-architecture)"
echo "  Testing as:     $TARGET_USER  (uid=$(id -u "$TARGET_USER"))"
echo "================================================================="

hdr "1. CLI TOOLS (terminal-only — should be on PATH for every user)"
for t in kubectl minikube docker; do asu "$t" "command -v $t"; done
# docker-compose may exist as standalone v1 OR as the v2 plugin 'docker compose'
if sudo -u "$TARGET_USER" bash -c "command -v docker-compose" >/dev/null 2>&1; then
  ok "docker-compose (v1 standalone) on PATH"
elif sudo -u "$TARGET_USER" bash -c "docker compose version" >/dev/null 2>&1; then
  ok "docker compose (v2 plugin) available"
else
  fail "neither 'docker-compose' nor 'docker compose' usable by $TARGET_USER (check docker group membership)"
fi

hdr "2. SYSTEM BROWSERS (Chrome / Edge .deb)"
for t in google-chrome microsoft-edge; do
  asu "$t binary on PATH" "command -v $t"
done
for d in google-chrome microsoft-edge; do
  if compgen -G "/usr/share/applications/${d}*.desktop" >/dev/null; then
    ok "$d .desktop entry present"
  else
    fail "$d .desktop entry missing"
  fi
done

hdr "3. APT-INSTALLED GUI APPS"
# Microsoft Edge .desktop check
if dpkg -s microsoft-edge-stable >/dev/null 2>&1; then
  if compgen -G "/usr/share/applications/microsoft-edge*.desktop" >/dev/null; then
    ok "microsoft-edge-stable installed + .desktop present"
  else
    warn "microsoft-edge-stable installed but no .desktop found"
  fi
else
  fail "microsoft-edge-stable not installed"
fi
# Azure VPN
if dpkg -s microsoft-azurevpnclient >/dev/null 2>&1; then
  if compgen -G "/usr/share/applications/*azurevpn*.desktop" >/dev/null \
     || compgen -G "/usr/share/applications/microsoft-azurevpn*.desktop" >/dev/null; then
    ok "microsoft-azurevpnclient installed + .desktop present"
  else
    warn "microsoft-azurevpnclient installed but no .desktop found"
  fi
else
  fail "microsoft-azurevpnclient not installed"
fi
# pgAdmin4 (Postgres tools team ships the .desktop as pgadmin4.desktop, not pgadmin4-desktop.desktop)
if dpkg -s pgadmin4-desktop >/dev/null 2>&1; then
  if compgen -G "/usr/share/applications/pgadmin4*.desktop" >/dev/null; then
    ok "pgadmin4-desktop installed + .desktop present"
  else
    warn "pgadmin4-desktop installed but no .desktop found"
  fi
else
  fail "pgadmin4-desktop not installed"
fi

hdr "4. DOCKER DESKTOP"
if dpkg -s docker-desktop >/dev/null 2>&1; then
  ok "docker-desktop package installed"
  [[ -f /usr/share/applications/docker-desktop.desktop ]] && ok ".desktop present" || warn ".desktop missing"
  asu "user can run 'docker version'" "docker version"
else
  fail "docker-desktop not installed"
fi

hdr "5. PYCHARM at /opt/pycharm"
if [[ -d /opt/pycharm ]]; then
  ok "/opt/pycharm exists"
  ls -ld /opt/pycharm
  for launcher in /opt/pycharm/bin/pycharm.sh /opt/pycharm/bin/pycharm; do
    if [[ -e "$launcher" ]]; then
      ls -l "$launcher"
      asu "launcher executable by $TARGET_USER" "test -x '$launcher'"
      break
    fi
  done
  if compgen -G "/usr/share/applications/pycharm*.desktop" >/dev/null \
     || compgen -G "/usr/share/applications/jetbrains-pycharm*.desktop" >/dev/null; then
    ok "PyCharm .desktop present (in launcher)"
  else
    warn "no PyCharm .desktop — not in launcher"
  fi
else
  fail "/opt/pycharm missing"
fi

hdr "6. JETBRAINS TOOLBOX at /opt/jetbrains-toolbox"
if [[ -d /opt/jetbrains-toolbox ]]; then
  ok "/opt/jetbrains-toolbox exists"
  ls -ld /opt/jetbrains-toolbox
  for tb in /opt/jetbrains-toolbox/jetbrains-toolbox /opt/jetbrains-toolbox/bin/jetbrains-toolbox; do
    [[ -x "$tb" ]] && { ok "toolbox launcher: $tb"; asu "user can stat it" "test -r '$tb' && test -x '$tb'"; break; }
  done
else
  warn "/opt/jetbrains-toolbox missing"
fi

hdr "7. DR. SPRINTO APPIMAGE"
if [[ -f /opt/altiushub/DrSprinto.AppImage ]]; then
  ls -l /opt/altiushub/DrSprinto.AppImage
  asu "AppImage readable+executable by $TARGET_USER" "test -r /opt/altiushub/DrSprinto.AppImage && test -x /opt/altiushub/DrSprinto.AppImage"
else
  fail "/opt/altiushub/DrSprinto.AppImage missing"
fi
[[ -L /usr/local/bin/drsprinto ]] && ok "/usr/local/bin/drsprinto symlink present" || warn "no /usr/local/bin/drsprinto symlink"
asu "drsprinto on PATH" "command -v drsprinto"
if dpkg -l 2>/dev/null | grep -qE '^ii  +libfuse2(t64)? '; then
  ok "libfuse2 runtime installed"
else
  fail "libfuse2 / libfuse2t64 NOT installed — AppImage cannot launch"
fi
[[ -f /usr/share/applications/drsprinto.desktop ]] && ok "drsprinto.desktop present" || warn "no drsprinto.desktop — won't show in launcher"

hdr "8. FLATPAK SYSTEM APPS"
if command -v flatpak >/dev/null 2>&1; then
  ok "flatpak installed ($(flatpak --version 2>/dev/null))"
  echo "  System-installed flatpaks:"
  flatpak list --system --columns=application,name 2>/dev/null | sed 's/^/    /' || echo "    (none)"
  echo ""
  echo "  Flathub remote configured?"
  if flatpak remotes --system 2>/dev/null | grep -q flathub; then ok "flathub remote present"; else fail "flathub remote missing"; fi
  echo ""
  if [[ -f /etc/profile.d/flatpak.sh ]]; then
    ok "/etc/profile.d/flatpak.sh present (sets XDG_DATA_DIRS)"
  else
    fail "/etc/profile.d/flatpak.sh missing — user shells won't see flatpak exports"
  fi
  echo ""
  echo "  $TARGET_USER's effective XDG_DATA_DIRS (login shell):"
  xdg=$(sudo -u "$TARGET_USER" bash -lc 'echo "$XDG_DATA_DIRS"' 2>/dev/null)
  echo "    $xdg"
  # Check specifically for the SYSTEM flatpak path, not user-local — user-local
  # alone isn't enough to see system-installed flatpaks in the launcher.
  if [[ "$xdg" == *"/var/lib/flatpak/exports/share"* ]]; then
    ok "XDG_DATA_DIRS includes SYSTEM flatpak exports (/var/lib/flatpak/exports/share)"
  else
    fail "XDG_DATA_DIRS missing /var/lib/flatpak/exports/share — system flatpaks invisible in launcher until user logs out + back in"
  fi
  echo ""
  echo "  Flatpak desktop exports on disk:"
  ls -la /var/lib/flatpak/exports/share/applications/ 2>/dev/null | sed 's/^/    /' || echo "    (none)"
else
  fail "flatpak binary not installed — none of the 6 Flathub apps can work"
fi

hdr "9. SUMMARY HINT"
SELF_URL="https://raw.githubusercontent.com/LolzMartiz/Arc-Angel/refs/heads/main/altiushub-verify-access.sh"
echo "  Re-run as a different user:"
echo "    curl -fsSL $SELF_URL | sudo bash -s <username>"
echo "  Test the AltiusHub admin user (if created):"
echo "    curl -fsSL $SELF_URL | sudo bash -s AltiusHub"
echo ""
