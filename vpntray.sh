#!/bin/bash
# launch vpntray, install deps if needed
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
[ "$EUID" -ne 0 ] && exec sudo -E bash "$0" "$@"

missing=()
command -v openvpn &>/dev/null || missing+=("openvpn")
python3 -c "import PyQt5.QtWebEngineWidgets" &>/dev/null 2>&1 || missing+=("python3-pyqt5.qtwebengine")
python3 -c "import PyQt5" &>/dev/null 2>&1 || missing+=("python3-pyqt5")

if [ ${#missing[@]} -ne 0 ]; then
    echo "[*] installing: ${missing[*]}"
    apt-get update -qq && apt-get install -y -qq "${missing[@]}"
fi

[ ! -f /etc/openvpn/update-resolv-conf ] && \
    apt-get install -y -qq openvpn-systemd-resolved resolvconf 2>/dev/null || true

exec python3 "${DIR}/vpntray.py" "$@"
