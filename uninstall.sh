#!/bin/bash
set -e
[ "$EUID" -ne 0 ] && echo "run as root" && exit 1
U="${SUDO_USER:-$USER}"; H=$(eval echo ~"$U")
pkill -f "vpntray.py" 2>/dev/null || true
iptables -D OUTPUT -j VPNTRAY_KS 2>/dev/null
iptables -F VPNTRAY_KS 2>/dev/null
iptables -X VPNTRAY_KS 2>/dev/null || true
rm -rf /opt/vpntray /usr/local/bin/vpntray /usr/share/applications/vpntray.desktop
rm -f "${H}/.config/autostart/vpntray.desktop" /etc/sudoers.d/vpntray
# clean up icons
rm -f /usr/share/icons/hicolor/scalable/apps/vpntray.svg
for sz in 16 22 32 48 64 128 256; do
    rm -f "/usr/share/icons/hicolor/${sz}x${sz}/apps/vpntray.png"
done
gtk-update-icon-cache /usr/share/icons/hicolor 2>/dev/null || true
echo "removed. user data still at ${H}/.vpntray/"
