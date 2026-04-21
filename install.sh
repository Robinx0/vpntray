#!/bin/bash
# vpntray installer - sets up /opt/vpntray, sudoers, autostart, menu entry, icons
set -e

INST="/opt/vpntray"
DIR="$(cd "$(dirname "$0")" && pwd)"
U="${SUDO_USER:-$USER}"
H=$(eval echo ~"$U")

[ "$EUID" -ne 0 ] && echo "run as root: sudo bash install.sh" && exit 1

echo "[1/7] deps..."
m=()
command -v openvpn &>/dev/null || m+=("openvpn")
python3 -c "import PyQt5" &>/dev/null 2>&1 || m+=("python3-pyqt5")
python3 -c "import PyQt5.QtWebEngineWidgets" &>/dev/null 2>&1 || m+=("python3-pyqt5.qtwebengine")
python3 -c "import PyQt5.QtSvg" &>/dev/null 2>&1 || m+=("python3-pyqt5.qtsvg")
[ ${#m[@]} -ne 0 ] && apt-get update -qq && apt-get install -y -qq "${m[@]}"
[ ! -f /etc/openvpn/update-resolv-conf ] && \
    apt-get install -y -qq openvpn-systemd-resolved resolvconf 2>/dev/null || true

echo "[2/7] copying to $INST..."
mkdir -p "$INST" "$INST/icons"
cp -f "${DIR}/vpntray.py" "${DIR}/vpntray.sh" "$INST/"
chmod +x "${INST}/vpntray.sh" "${INST}/vpntray.py"

# if the caller bundled an icons/ dir, use it. otherwise write the svg ourselves.
if [ -f "${DIR}/icons/vpntray.svg" ]; then
    cp -f "${DIR}/icons/vpntray.svg" "$INST/icons/"
else
    cat > "$INST/icons/vpntray.svg" <<'SVGEOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256">
  <defs>
    <linearGradient id="shield" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#00e676"/>
      <stop offset="100%" stop-color="#00a152"/>
    </linearGradient>
    <linearGradient id="shine" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#ffffff" stop-opacity="0.28"/>
      <stop offset="55%" stop-color="#ffffff" stop-opacity="0"/>
    </linearGradient>
    <radialGradient id="glow" cx="0.5" cy="0.35" r="0.6">
      <stop offset="0%" stop-color="#ffffff" stop-opacity="0.18"/>
      <stop offset="100%" stop-color="#ffffff" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <path d="M128 16 C 185 16, 210 24, 210 72 C 210 140, 180 200, 128 240 C 76 200, 46 140, 46 72 C 46 24, 71 16, 128 16 Z" fill="url(#shield)" stroke="#00e676" stroke-width="2"/>
  <path d="M128 16 C 185 16, 210 24, 210 72 C 210 140, 180 200, 128 240 C 76 200, 46 140, 46 72 C 46 24, 71 16, 128 16 Z" fill="url(#shine)"/>
  <path d="M128 16 C 185 16, 210 24, 210 72 C 210 140, 180 200, 128 240 C 76 200, 46 140, 46 72 C 46 24, 71 16, 128 16 Z" fill="url(#glow)"/>
  <g stroke="#ffffff" stroke-width="1.5" fill="none" opacity="0.28">
    <ellipse cx="128" cy="110" rx="52" ry="52"/>
    <ellipse cx="128" cy="110" rx="22" ry="52"/>
    <line x1="76" y1="110" x2="180" y2="110"/>
  </g>
  <g stroke="#ffffff" stroke-width="5.5" fill="none" stroke-linecap="round" stroke-linejoin="round">
    <circle cx="128" cy="142" r="14"/>
    <path d="M119 154 L119 178 Q 119 184 125 184 L 131 184 Q 137 184 137 178 L 137 154"/>
  </g>
  <circle cx="88" cy="60" r="3.5" fill="#ffffff" opacity="0.5"/>
  <circle cx="168" cy="60" r="3.5" fill="#ffffff" opacity="0.5"/>
  <circle cx="128" cy="42" r="3.5" fill="#ffffff" opacity="0.5"/>
  <g stroke="#ffffff" stroke-width="1.2" opacity="0.3">
    <line x1="91" y1="62" x2="108" y2="72"/>
    <line x1="165" y1="62" x2="148" y2="72"/>
    <line x1="128" y1="45" x2="128" y2="72"/>
  </g>
</svg>
SVGEOF
fi

echo "[3/7] generating icon variants..."
# inline python: generate on/off/busy svgs + pngs at common sizes
python3 - "$INST/icons" <<'PYEOF'
import sys, re
from pathlib import Path
from PyQt5.QtWidgets import QApplication
from PyQt5.QtSvg import QSvgRenderer
from PyQt5.QtCore import Qt, QByteArray
from PyQt5.QtGui import QPixmap, QPainter

icons_dir = Path(sys.argv[1])
base = (icons_dir / "vpntray.svg").read_text()

states = {
    "on":   ("#00e676", "#00a152"),
    "off":  ("#ff5252", "#b71c1c"),
    "busy": ("#ffab00", "#c77700"),
}
sizes = [16, 22, 32, 48, 64, 128, 256]

app = QApplication.instance() or QApplication(sys.argv)

for state, (main, shade) in states.items():
    svg = base.replace('stop-color="#00e676"', f'stop-color="{main}"')
    svg = svg.replace('stop-color="#00a152"', f'stop-color="{shade}"')
    svg = svg.replace('stroke="#00e676"', f'stroke="{main}"')
    (icons_dir / f"vpntray-{state}.svg").write_text(svg)
    renderer = QSvgRenderer(QByteArray(svg.encode()))
    for sz in sizes:
        pm = QPixmap(sz, sz)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing)
        p.setRenderHint(QPainter.SmoothPixmapTransform)
        renderer.render(p)
        p.end()
        pm.save(str(icons_dir / f"vpntray-{state}-{sz}.png"))
    print(f"  {state}: {len(sizes)} sizes")
PYEOF

echo "[4/7] installing to hicolor theme..."
install -D -m 644 "${INST}/icons/vpntray-on.svg" /usr/share/icons/hicolor/scalable/apps/vpntray.svg
for sz in 16 22 32 48 64 128 256; do
    install -D -m 644 "${INST}/icons/vpntray-on-${sz}.png" \
        "/usr/share/icons/hicolor/${sz}x${sz}/apps/vpntray.png"
done
gtk-update-icon-cache /usr/share/icons/hicolor 2>/dev/null || true

echo "[5/7] sudoers..."
cat > /etc/sudoers.d/vpntray <<EOF
$U ALL=(root) NOPASSWD: /opt/vpntray/vpntray.sh
$U ALL=(root) NOPASSWD: /usr/bin/python3 /opt/vpntray/vpntray.py
EOF
chmod 440 /etc/sudoers.d/vpntray

echo "[6/7] autostart + menu entry..."
mkdir -p "${H}/.config/autostart"
cat > "${H}/.config/autostart/vpntray.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=VPNTray
Exec=sudo /opt/vpntray/vpntray.sh
Icon=vpntray
Terminal=false
Hidden=false
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Delay=3
EOF
chown "${U}:${U}" "${H}/.config/autostart/vpntray.desktop"

cat > /usr/share/applications/vpntray.desktop <<EOF
[Desktop Entry]
Type=Application
Name=VPNTray
Comment=OpenVPN tray client
Exec=sudo /opt/vpntray/vpntray.sh
Icon=vpntray
Terminal=false
Categories=Network;Security;
EOF

echo "[7/7] cli shortcut..."
printf '#!/bin/bash\nexec sudo /opt/vpntray/vpntray.sh "$@"\n' > /usr/local/bin/vpntray
chmod +x /usr/local/bin/vpntray

update-desktop-database /usr/share/applications 2>/dev/null || true

echo ""
echo "done. run 'vpntray' or find it in your app menu."
