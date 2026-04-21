#!/usr/bin/env python3
# vpntray - openvpn tray client for kali
# dashboard is html/css rendered in QWebEngineView, icons are svg from icons/
#
# if you're reading this and wondering why the dashboard isn't qt widgets:
# qss can't do half of what modern css can (gradients on arbitrary widgets,
# rgba backgrounds, backdrop filters). trying to make it pretty in qss is
# suffering.

import sys, os, signal, json, shutil, subprocess, socket, secrets
from pathlib import Path
from datetime import datetime

# chromium needs these when running as root
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--no-sandbox"
if not os.environ.get("XDG_RUNTIME_DIR"):
    rd = f"/tmp/runtime-{os.getuid()}"
    os.makedirs(rd, mode=0o700, exist_ok=True)
    os.environ["XDG_RUNTIME_DIR"] = rd

from PyQt5.QtWidgets import (
    QApplication, QSystemTrayIcon, QMenu, QAction,
    QVBoxLayout, QFileDialog, QDialog
)
from PyQt5.QtGui import (
    QIcon, QPixmap, QPainter, QColor, QPen, QBrush,
    QLinearGradient, QRadialGradient, QPainterPath
)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal, QUrl, QPoint
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage, QWebEngineSettings

# paths
APP_DIR    = Path.home() / ".vpntray"
CONF_DIR   = APP_DIR / "profiles"
LOG_DIR    = APP_DIR / "logs"
STATE_FILE = APP_DIR / "state.json"
MGMT_HOST  = "127.0.0.1"
MGMT_PORT  = 17505
MGMT_PASS  = None

for d in (APP_DIR, CONF_DIR, LOG_DIR):
    d.mkdir(parents=True, exist_ok=True)


# -- tray icon --

# tries to load packaged state icons from /opt/vpntray/icons/ first,
# falls back to drawing with QPainter if the files aren't there
ICON_DIR = Path("/opt/vpntray/icons")
if not ICON_DIR.exists():
    # dev mode -- check next to this script
    ICON_DIR = Path(__file__).parent / "icons"

def load_icon(state):
    """state in ('on','off','busy'). Returns QIcon."""
    # prefer svg for crisp rendering at any size
    svg = ICON_DIR / f"vpntray-{state}.svg"
    if svg.exists():
        return QIcon(str(svg))
    # fall back to pre-rendered png (64px)
    png = ICON_DIR / f"vpntray-{state}-64.png"
    if png.exists():
        return QIcon(str(png))
    # last resort: paint one on the fly
    return _paint_fallback(state)


def _paint_fallback(state):
    colors = {"on": "#00e676", "off": "#ff5252", "busy": "#ffab00"}
    symbols = {"on": "check", "off": "x", "busy": "dots"}
    color = colors.get(state, "#ff5252")
    sym = symbols.get(state, "x")
    sz = 64
    pm = QPixmap(sz, sz)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)

    shield = QPainterPath()
    cx, t, b, w = sz/2, 4, sz-4, sz-8
    shield.moveTo(cx, t)
    shield.cubicTo(cx+w*0.52, t, cx+w*0.52, (t+b)*0.42, cx, b)
    shield.cubicTo(cx-w*0.52, (t+b)*0.42, cx-w*0.52, t, cx, t)

    grad = QLinearGradient(0, 0, 0, sz)
    qc = QColor(color)
    grad.setColorAt(0, qc.lighter(150))
    grad.setColorAt(1, qc.darker(150))
    p.setBrush(QBrush(grad))
    p.setPen(QPen(qc.lighter(110), 1.5))
    p.drawPath(shield)

    p.setPen(QPen(QColor("#fff"), 3.5, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    if sym == "check":
        p.drawLine(21, 34, 28, 42); p.drawLine(28, 42, 43, 24)
    elif sym == "dots":
        p.setPen(Qt.NoPen); p.setBrush(QColor("#fff"))
        for x in (24, 32, 40): p.drawEllipse(QPoint(x, 33), 2, 2)
    else:
        p.drawLine(23, 24, 41, 42); p.drawLine(41, 24, 23, 42)
    p.end()
    return QIcon(pm)


def make_tray_icon(color, symbol="x"):
    # shim for compatibility -- map color/symbol to state
    if symbol == "check": return load_icon("on")
    if symbol == "dots": return load_icon("busy")
    return load_icon("off")


# -- state --

DEFAULTS = {
    "last_profile": None, "auto_connect": False, "dns_fix": True,
    "killswitch": False, "reconnect": True, "reconnect_delay": 5,
    "theme": "tactical",
}

def load_state():
    if STATE_FILE.exists():
        try:
            s = json.loads(STATE_FILE.read_text())
            for k, v in DEFAULTS.items(): s.setdefault(k, v)
            return s
        except: pass
    return dict(DEFAULTS)

def save_state(s):
    STATE_FILE.write_text(json.dumps(s, indent=2))


# -- mgmt interface --

class MgmtClient:
    def __init__(self):
        self._sock = None

    def _ensure(self):
        if self._sock:
            return True
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((MGMT_HOST, MGMT_PORT))
            g = s.recv(4096).decode(errors="replace")
            if MGMT_PASS and "ENTER PASSWORD" in g:
                s.sendall((MGMT_PASS + "\r\n").encode())
                s.recv(4096)
            self._sock = s
            return True
        except:
            self._sock = None
            return False

    def _query(self, cmd):
        if not self._ensure():
            return ""
        try:
            self._sock.sendall((cmd + "\r\n").encode())
            buf = b""
            while True:
                try:
                    chunk = self._sock.recv(4096)
                    if not chunk:
                        self.close()
                        break
                    buf += chunk
                    if b"END\r\n" in buf or b"SUCCESS" in buf or b"ERROR" in buf:
                        break
                except socket.timeout:
                    # partial response -- socket is now in a bad state, drop it
                    self.close()
                    break
            return buf.decode(errors="replace")
        except:
            self.close()
            return ""

    def close(self):
        try: self._sock.close()
        except: pass
        self._sock = None

    def get_status(self):
        info = {"bytes_in": 0, "bytes_out": 0, "local_ip": "", "remote_ip": "", "tun_dev": ""}
        try:
            for line in self._query("status 2").split("\n"):
                if line.startswith("TCP/UDP read bytes,"):
                    try: info["bytes_in"] = int(line.split(",")[1])
                    except (ValueError, IndexError): pass
                elif line.startswith("TCP/UDP write bytes,"):
                    try: info["bytes_out"] = int(line.split(",")[1])
                    except (ValueError, IndexError): pass
            for line in self._query("state").split("\n"):
                parts = line.strip().split(",")
                if len(parts) >= 4 and parts[1] in ("CONNECTED", "CONNECTING", "RECONNECTING", "WAIT"):
                    if len(parts) >= 5 and parts[3]: info["local_ip"] = parts[3]
                    if len(parts) >= 6 and parts[4]: info["remote_ip"] = parts[4]
            # try to detect the actual tun/tap device
            for line in self._query("status 2").split("\n"):
                if line.startswith("HEADER,") or not line.strip():
                    continue
                # CLIENT_LIST or ROUTING_TABLE entries mention the device
                if "tun" in line or "tap" in line:
                    for word in line.replace(",", " ").split():
                        if word.startswith("tun") or word.startswith("tap"):
                            if word[3:].isdigit():
                                info["tun_dev"] = word
                                break
        except Exception:
            pass
        return info

    def fetch_log(self, n=100):
        return self._query(f"log {n}")


# -- kill switch --

KS_CHAIN = "VPNTRAY_KS"

def ks_enable(server_ip, tun="tun0"):
    for c in [
        f"iptables -N {KS_CHAIN} 2>/dev/null || iptables -F {KS_CHAIN}",
        f"iptables -A {KS_CHAIN} -o lo -j ACCEPT",
        f"iptables -A {KS_CHAIN} -o {tun} -j ACCEPT",
        f"iptables -A {KS_CHAIN} -d {server_ip} -j ACCEPT",
        f"iptables -A {KS_CHAIN} -d 10.0.0.0/8 -j ACCEPT",
        f"iptables -A {KS_CHAIN} -d 172.16.0.0/12 -j ACCEPT",
        f"iptables -A {KS_CHAIN} -d 192.168.0.0/16 -j ACCEPT",
        f"iptables -A {KS_CHAIN} -j DROP",
        f"iptables -I OUTPUT 1 -j {KS_CHAIN}",
    ]: subprocess.run(c, shell=True, capture_output=True)

def ks_disable():
    for c in [
        f"iptables -D OUTPUT -j {KS_CHAIN} 2>/dev/null",
        f"iptables -F {KS_CHAIN} 2>/dev/null",
        f"iptables -X {KS_CHAIN} 2>/dev/null",
    ]: subprocess.run(c, shell=True, capture_output=True)


# -- vpn worker thread --

class VPNWorker(QThread):
    log_line = pyqtSignal(str)
    vpn_status = pyqtSignal(str)
    tun_detected = pyqtSignal(str)  # emits "tun0", "tap1", etc.

    # hide mgmt chatter from the ui
    _NOISE = ("MANAGEMENT: Client", "MANAGEMENT: CMD")

    def __init__(self, config_path, overrides=None):
        super().__init__()
        self.config_path = config_path
        self.overrides = overrides or {}
        self._proc = None
        self._stopping = False

    def _build_cmd(self):
        global MGMT_PASS
        MGMT_PASS = secrets.token_hex(16)
        pw = APP_DIR / ".mgmt_pw"
        pw.write_text(MGMT_PASS)
        pw.chmod(0o600)

        cmd = ["openvpn", "--config", self.config_path,
               "--management", MGMT_HOST, str(MGMT_PORT), str(pw),
               "--management-query-passwords"]
        o = self.overrides

        for key, flag in [("proto","--proto"),("dev_type","--dev"),("auth","--auth"),
                          ("tls_version_min","--tls-version-min")]:
            v = o.get(key, "(default)")
            if v and v != "(default)": cmd += [flag, v]

        cipher = o.get("cipher", "(default)")
        if cipher and cipher != "(default)":
            f = "--data-ciphers" if cipher in ("AES-256-GCM","AES-128-GCM","CHACHA20-POLY1305") else "--cipher"
            cmd += [f, cipher]

        for key, flag in [("port","--port"),("tun_mtu","--tun-mtu"),("fragment","--fragment"),
                          ("mssfix","--mssfix"),("ping","--ping"),("ping_restart","--ping-restart"),
                          ("sndbuf","--sndbuf"),("rcvbuf","--rcvbuf"),
                          ("txqueuelen","--txqueuelen")]:
            v = o.get(key)
            if v: cmd += [flag, str(v)]

        # reneg_sec=0 is valid (disables renegotiation), so check None explicitly
        reneg = o.get("reneg_sec")
        if reneg is not None and reneg != "":
            cmd += ["--reneg-sec", str(reneg)]

        ki, kt = o.get("keepalive_interval"), o.get("keepalive_timeout")
        if ki and kt: cmd += ["--keepalive", str(ki), str(kt)]

        comp = o.get("compress", "(none)")
        if comp != "(none)":
            cmd += (["--comp-lzo","adaptive"] if comp == "lzo" else ["--compress", comp])

        if o.get("reconnect", True):
            cmd += ["--connect-retry", str(o.get("reconnect_delay",5)), "--connect-retry-max", "0"]
        else:
            cmd += ["--connect-retry-max", "1"]

        pt, ph, pp = o.get("proxy_type"), o.get("proxy_host"), o.get("proxy_port")
        if pt and ph and pp:
            if pt == "http": cmd += ["--http-proxy", ph, str(pp), o.get("proxy_auth_file") or "auto"]
            elif pt == "socks5": cmd += ["--socks-proxy", ph, str(pp)]

        if o.get("dns_fix", True):
            up = "/etc/openvpn/update-resolv-conf"
            if os.path.isfile(up): cmd += ["--up",up,"--down",up,"--script-security","2"]

        if o.get("route_nopull"): cmd += ["--route-nopull"]
        for ln in o.get("custom_routes","").strip().split("\n"):
            if ln.strip(): cmd += ["--route"] + ln.strip().split()

        auth = o.get("auth_user_pass")
        if auth: cmd += ["--auth-user-pass", auth]

        rg = o.get("redirect_gw", "(default)")
        if rg != "(default)": cmd += ["--redirect-gateway"] + rg.split()

        cmd += ["--verb", str(o.get("verbosity","3")), "--persist-tun"]
        if o.get("float"): cmd += ["--float"]
        if o.get("nobind", True): cmd += ["--nobind"]

        for ln in o.get("pull_filter","").strip().split("\n"):
            if ln.strip(): cmd += ["--pull-filter"] + ln.strip().split(None,1)
        for ln in o.get("extra_directives","").strip().split("\n"):
            if ln.strip() and not ln.strip().startswith("#"): cmd += ln.strip().split()

        return cmd

    def run(self):
        cmd = self._build_cmd()
        logfile = LOG_DIR / f"vpn_{datetime.now():%Y%m%d_%H%M%S}.log"
        self.log_line.emit(f"[CMD] {' '.join(cmd)}")
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            with open(logfile, "w") as lf:
                for line in iter(self._proc.stdout.readline, ""):
                    if self._stopping: break
                    line = line.rstrip()
                    lf.write(line + "\n"); lf.flush()
                    if any(n in line for n in self._NOISE): continue
                    self.log_line.emit(line)
                    if "Initialization Sequence Completed" in line: self.vpn_status.emit("connected")
                    elif "AUTH_FAILED" in line: self.vpn_status.emit("error")
                    elif "TLS Error" in line or "Connection refused" in line: self.vpn_status.emit("error")
                    elif "SIGUSR1" in line or "Restart pause" in line: self.vpn_status.emit("reconnecting")
                    elif "TUN/TAP device" in line and "opened" in line:
                        for word in line.split():
                            if (word.startswith("tun") or word.startswith("tap")) and word[3:].isdigit():
                                self.tun_detected.emit(word)
                                break
            self._proc.wait()
        except FileNotFoundError:
            self.log_line.emit("[!] openvpn not found"); self.vpn_status.emit("error")
        except Exception as e:
            self.log_line.emit(f"[!] {e}"); self.vpn_status.emit("error")
        finally:
            # make sure pipe is closed so the thread can exit cleanly
            if self._proc and self._proc.stdout:
                try: self._proc.stdout.close()
                except: pass
            if not self._stopping: self.vpn_status.emit("disconnected")

    def stop(self):
        self._stopping = True
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try: self._proc.wait(timeout=8)
            except subprocess.TimeoutExpired: self._proc.kill()


# js -> python communication. js calls console.log('BRIDGE:cmd:json_data')
# and we intercept it here instead of going through QWebChannel, which needs
# extra packages (python3-pyqt5.qtwebchannel) and breaks silently if the
# qrc:///qtwebchannel/qwebchannel.js resource can't load.

class BridgePage(QWebEnginePage):
    def __init__(self, app, parent=None):
        super().__init__(parent)
        self.app = app

    def javaScriptConsoleMessage(self, level, message, line, source):
        if not message.startswith("BRIDGE:"):
            return
        parts = message.split(":", 2)
        cmd = parts[1] if len(parts) > 1 else ""
        raw = parts[2] if len(parts) > 2 else "{}"
        try:
            data = json.loads(raw)
        except:
            data = {}
        self.app.handle_bridge(cmd, data)


# -- main app --

class VPNTrayApp:
    def __init__(self):
        self.qapp = QApplication(sys.argv)
        self.qapp.setQuitOnLastWindowClosed(False)
        self.qapp.setApplicationName("VPNTray")

        self.state = load_state()
        self.worker = None
        self.mgmt = MgmtClient()
        self.profile = ""
        self.connected_at = None
        self._ks_active = False
        self._soft_recon = False
        self._tun_ip = ""
        self._tun_dev = "tun0"  # updated from openvpn output
        self._overrides = {}
        self._log_buffer = []   # holds lines emitted before the page is ready
        self._page_ready = False

        # tray
        self.tray = QSystemTrayIcon()
        self._set_tray("disconnected")
        self.tray.setToolTip("VPNTray - Disconnected")
        self.tray.activated.connect(lambda r: self.show_dash() if r == QSystemTrayIcon.Trigger else None)

        # menu
        self.menu = QMenu()
        self.status_act = QAction("Disconnected")
        self.status_act.setEnabled(False)
        self.menu.addAction(self.status_act)
        self.menu.addSeparator()
        self.qc_menu = self.menu.addMenu("Quick Connect")
        self._build_qc()
        self.dc_act = QAction("Disconnect")
        self.dc_act.triggered.connect(self.do_disconnect)
        self.dc_act.setEnabled(False)
        self.menu.addAction(self.dc_act)
        self.menu.addSeparator()
        a = QAction("Dashboard"); a.triggered.connect(self.show_dash); self.menu.addAction(a)
        self.menu.addSeparator()
        a = QAction("Quit"); a.triggered.connect(self._quit); self.menu.addAction(a)
        self.tray.setContextMenu(self.menu)
        self.tray.show()

        # window + webview
        self.win = QDialog()
        self.win.setWindowTitle("VPNTray")
        self.win.setWindowIcon(load_icon("off"))  # updates to on/busy via _set_tray
        self.win.setMinimumSize(740, 500)
        # match the saved theme so there's no ugly dark flash before the html loads
        bg_map = {"tactical": "#0a0e14", "mocha": "#1e1e2e", "latte": "#eff1f5"}
        self.win.setStyleSheet(f"background: {bg_map.get(self.state.get('theme','tactical'),'#0a0e14')};")
        lay = QVBoxLayout(self.win)
        lay.setContentsMargins(0,0,0,0)

        self.page = BridgePage(self)
        self.page.settings().setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, True)
        self.web = QWebEngineView()
        self.web.setPage(self.page)
        self.web.setHtml(HTML, QUrl("about:blank"))
        lay.addWidget(self.web)

        # timers
        self._tick_t = QTimer()
        self._tick_t.timeout.connect(self._tick)
        self._tick_t.start(1000)

        self._poll_t = QTimer()
        self._poll_t.timeout.connect(self._poll)
        self._poll_t.start(5000)

        # auto-connect
        if self.state.get("auto_connect") and self.state.get("last_profile"):
            name = self.state["last_profile"]
            for ext in (".ovpn", ".conf"):
                cfg = CONF_DIR / f"{name}{ext}"
                if cfg.exists():
                    QTimer.singleShot(2000, lambda c=str(cfg), n=name: self.do_connect(c, n, {}))
                    break

    # -- bridge handler --
    # all JS->Python communication goes through here
    def handle_bridge(self, cmd, data):
        if cmd == "connect":
            self.do_connect(data["path"], data["name"], self._overrides)
        elif cmd == "disconnect":
            self.do_disconnect()
        elif cmd == "setOverrides":
            # split: persistent app settings vs per-connection openvpn flags
            app_keys = ("auto_connect", "reconnect", "reconnect_delay", "dns_fix", "killswitch", "theme")
            dirty = False
            for k in app_keys:
                if k in data and self.state.get(k) != data[k]:
                    self.state[k] = data[k]
                    dirty = True
            if dirty:
                save_state(self.state)
            self._overrides = data
        elif cmd == "import":
            self._do_import()
        elif cmd == "remove":
            self._do_remove(data.get("name",""))
        elif cmd == "duplicate":
            self._do_duplicate(data.get("name",""), data.get("new_name",""))
        elif cmd == "getConfig":
            self._do_get_config(data.get("name",""))
        elif cmd == "refresh":
            self._push_profiles()
            self._build_qc()
        elif cmd == "openLogDir":
            subprocess.Popen(["xdg-open", str(LOG_DIR)])
        elif cmd == "fetchMgmt":
            log = self.mgmt.fetch_log(100) or "not reachable"
            # push each mgmt log line as a proper timestamped entry
            for line in log.split("\n"):
                line = line.strip()
                if line and not line.startswith("END") and not line.startswith("SUCCESS"):
                    self._push_log(f"[mgmt] {line}")
        elif cmd == "browseAuth":
            p, _ = QFileDialog.getOpenFileName(None, "Auth file")
            if p: self._js(f"document.getElementById('ov-authfile').value={json.dumps(p)}")
        elif cmd == "saveSettings":
            self.state.update(data)
            save_state(self.state)
        elif cmd == "getSettings":
            self._js(f"onSettings({json.dumps(self.state)})")
        elif cmd == "getVersion":
            self._js(f"onVersion({json.dumps(self._openvpn_version())})")
        elif cmd == "init":
            # page loaded, send initial data
            self._page_ready = True
            # drain any log lines that arrived before the page was ready
            for line in self._log_buffer:
                self._js(f"appendLog({json.dumps(line)})")
            self._log_buffer = []
            self._push_profiles()
            self._js(f"onSettings({json.dumps(self.state)})")
            self._js(f"onVersion({json.dumps(self._openvpn_version())})")

    def _openvpn_version(self):
        try:
            r = subprocess.run(["openvpn", "--version"], capture_output=True, text=True, timeout=5)
            return (r.stdout or r.stderr).split("\n")[0].strip()[:80]
        except Exception:
            return "(not found)"

    def _js(self, code):
        self.page.runJavaScript(code)

    def _push_profiles(self):
        profiles = sorted(CONF_DIR.glob("*.ovpn")) + sorted(CONF_DIR.glob("*.conf"))
        seen = set(); result = []
        for p in profiles:
            if p.stem not in seen:
                seen.add(p.stem)
                result.append({"name": p.stem, "file": p.name, "path": str(p)})
        self._js(f"onProfiles({json.dumps(result)})")
        self._build_qc()  # keep tray quick-connect in sync

    def _do_import(self):
        paths, _ = QFileDialog.getOpenFileNames(None, "Import Profiles", "",
                                                 "OpenVPN (*.ovpn *.conf);;All (*)")
        for src_path in paths:
            src = Path(src_path)
            dst = CONF_DIR / src.name
            if dst.suffix not in (".ovpn",".conf"): dst = dst.with_suffix(".ovpn")
            shutil.copy2(src, dst)
            # grab any referenced certs/keys from same dir
            try:
                for line in open(src):
                    for d in ("ca ","cert ","key ","tls-auth ","tls-crypt ",
                              "auth-user-pass ","crl-verify ","pkcs12 ","dh "):
                        if line.strip().startswith(d):
                            parts = line.strip().split(None, 1)
                            if len(parts) == 2:
                                ref = src.parent / parts[1]
                                if ref.is_file(): shutil.copy2(ref, CONF_DIR / ref.name)
            except: pass
            self._push_log(f"[+] Imported: {src.name}")
        self._push_profiles()

    def _do_remove(self, name):
        for ext in (".ovpn", ".conf"):
            p = CONF_DIR / f"{name}{ext}"
            if p.exists(): p.unlink()
        self._push_profiles()

    def _do_duplicate(self, name, new_name):
        if not new_name or name == new_name:
            return
        for ext in (".ovpn", ".conf"):
            src = CONF_DIR / f"{name}{ext}"
            if src.exists():
                dst = CONF_DIR / f"{new_name}{ext}"
                if dst.exists():
                    self._push_log(f"[!] Duplicate failed -- {new_name}{ext} already exists")
                    return
                shutil.copy2(src, dst)
                self._push_log(f"[+] Duplicated: {name} -> {new_name}")
                break
        self._push_profiles()

    def _do_get_config(self, name):
        for ext in (".ovpn", ".conf"):
            p = CONF_DIR / f"{name}{ext}"
            if p.exists():
                self._js(f"onConfig({json.dumps(p.read_text())})")
                return
        self._js("onConfig('(empty)')")

    # -- tray --

    def _set_tray(self, status):
        state_map = {
            "connected": "on",
            "disconnected": "off",
            "connecting": "busy",
            "reconnecting": "busy",
            "error": "off",
        }
        state = state_map.get(status, "off")
        icon = load_icon(state)
        self.tray.setIcon(icon)
        # window may not exist yet during __init__
        if getattr(self, "win", None) is not None:
            self.win.setWindowIcon(icon)
        # some DEs cache the tray pixmap; hide/show forces a refresh
        self.tray.hide(); self.tray.show()

    def _build_qc(self):
        self.qc_menu.clear()
        profiles = sorted(CONF_DIR.glob("*.ovpn")) + sorted(CONF_DIR.glob("*.conf"))
        seen = set()
        if not profiles:
            a = QAction("(no profiles)"); a.setEnabled(False); self.qc_menu.addAction(a)
        for p in profiles:
            if p.stem in seen: continue
            seen.add(p.stem)
            a = QAction(p.stem)
            path, name = str(p), p.stem
            a.triggered.connect(lambda _, _p=path, _n=name: self.do_connect(_p, _n, {}))
            self.qc_menu.addAction(a)

    def show_dash(self):
        self._build_qc()
        self._push_profiles()
        self.win.show(); self.win.raise_(); self.win.activateWindow()

    # -- connect/disconnect --

    def do_connect(self, config, name, overrides):
        # if already running, tear it down first (non-blocking from UI perspective)
        if self.worker and self.worker.isRunning():
            self._push_log("[*] Stopping previous connection...")
            self.worker.stop()
            self.worker.wait(6000)
            self.worker = None

        self.profile = name
        self.state["last_profile"] = name
        save_state(self.state)
        self._soft_recon = False
        self._tun_ip = ""
        self._tun_dev = "tun0"
        self.mgmt.close()

        self._push_log(f"[*] Connecting -> {name}")
        self._set_status("connecting")

        self.worker = VPNWorker(config, overrides)
        self.worker.log_line.connect(self._push_log)
        self.worker.vpn_status.connect(self._on_vpn)
        self.worker.tun_detected.connect(self._on_tun_detected)
        self.worker.start()

    def do_disconnect(self):
        if self.worker:
            self._push_log("[*] Disconnecting...")
            self.worker.stop()
            self.worker.wait(6000)
            self.worker = None
        self.mgmt.close()
        self._tun_ip = ""
        if self._ks_active:
            ks_disable()
            self._ks_active = False
            self._push_log("[*] Kill switch off.")
        # clean up mgmt password file
        try:
            pw = APP_DIR / ".mgmt_pw"
            if pw.exists(): pw.unlink()
        except: pass
        self._set_status("disconnected")

    def _on_tun_detected(self, name):
        self._tun_dev = name

    def _on_vpn(self, status):
        if status == "connected":
            if not self._soft_recon:
                self.connected_at = datetime.now()
            self._soft_recon = False
            self.tray.showMessage("VPNTray", f"Connected: {self.profile}",
                                  QSystemTrayIcon.Information, 3000)
            if self._overrides.get("killswitch") and not self._ks_active:
                try:
                    info = self.mgmt.get_status()
                    rip = info.get("remote_ip","")
                    if rip:
                        ks_enable(rip, self._tun_dev)
                        self._ks_active = True
                        self._push_log(f"[*] Kill switch ON ({rip} via {self._tun_dev})")
                except: pass
        elif status == "reconnecting":
            self._soft_recon = True
            self.mgmt.close()
        elif status == "error":
            self.tray.showMessage("VPNTray", "Connection error", QSystemTrayIcon.Warning, 5000)
        self._set_status(status)

    def _set_status(self, status):
        self._set_tray(status)
        tip = f"VPNTray - {status.title()}"
        if status == "connected":
            tip += f"\n{self.profile}"
            if self._tun_ip: tip += f"\n{self._tun_ip}"
        self.tray.setToolTip(tip)
        self.status_act.setText(status.title() + (f" - {self.profile}" if status == "connected" else ""))
        self.dc_act.setEnabled(status in ("connected","connecting","reconnecting"))
        self._js(f"onStatus({json.dumps(status)},{json.dumps(self.profile)})")
        if status == "disconnected":
            self.connected_at = None
            self._soft_recon = False
            self._tun_ip = ""

    def _push_log(self, text):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {text}"
        if not self._page_ready:
            # buffer early lines so we don't lose them before the webview loads
            self._log_buffer.append(line)
            if len(self._log_buffer) > 500:
                self._log_buffer = self._log_buffer[-500:]
            return
        self._js(f"appendLog({json.dumps(line)})")

    def _tick(self):
        if not self.connected_at: return
        d = int((datetime.now() - self.connected_at).total_seconds())
        h, r = divmod(d, 3600); m, s = divmod(r, 60)
        self._js(f"setUptime('{h:02d}:{m:02d}:{s:02d}')")

    def _poll(self):
        if not self.connected_at or not self.worker or not self.worker.isRunning():
            return
        try:
            info = self.mgmt.get_status()
            ip = info.get("local_ip", "")
            if ip and ip != self._tun_ip:
                self._tun_ip = ip
                self.tray.setToolTip(f"VPNTray - Connected\n{self.profile}\n{self._tun_ip}")
            self._js(f"onStats({json.dumps(info)})")
        except Exception as e:
            # don't spam the log -- only emit once per unique error
            msg = str(e)
            if msg != getattr(self, "_last_poll_err", None):
                self._last_poll_err = msg
                self._push_log(f"[!] poll error: {msg}")

    def _quit(self):
        self.do_disconnect()
        self.tray.hide()
        self.qapp.quit()

    def run(self):
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        sys.exit(self.qapp.exec_())


# the ui lives in this giant html blob. fonts come from google, icons are
# inline svg so they theme-swap nicely. no external js frameworks.

HTML = r"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --f:"IBM Plex Mono",monospace;
  /* tactical (default) — dark + high contrast */
  --bg:#0a0e14; --bg1:#0e1319; --bg2:#161c25; --bg3:#1d2430;
  --t0:#e8eef4; --t1:#a8b8c8; --t2:#6a7a8c; --t3:#3a4a5a;
  --grn:#00e676; --red:#ff5252; --amb:#ffab00; --cyn:#40c4ff;
  --accent-rgb:0,230,118;
  --border:rgba(255,255,255,.06);
  --border-strong:rgba(255,255,255,.1);
  --surface:rgba(255,255,255,.025);
  --surface-hover:rgba(255,255,255,.05);
  --input-bg:rgba(0,0,0,.2);
  --nav-bg:#080c11;
  --scroll:rgba(255,255,255,.08);
}
[data-theme="mocha"]{
  --bg:#1e1e2e; --bg1:#181825; --bg2:#313244; --bg3:#45475a;
  --t0:#cdd6f4; --t1:#bac2de; --t2:#9399b2; --t3:#6c7086;
  --grn:#a6e3a1; --red:#f38ba8; --amb:#f9e2af; --cyn:#89b4fa;
  --accent-rgb:166,227,161;
  --border:rgba(205,214,244,.08);
  --border-strong:rgba(205,214,244,.15);
  --surface:rgba(205,214,244,.035);
  --surface-hover:rgba(205,214,244,.07);
  --input-bg:rgba(17,17,27,.5);
  --nav-bg:#181825;
  --scroll:rgba(205,214,244,.12);
}
[data-theme="latte"]{
  --bg:#eff1f5; --bg1:#e6e9ef; --bg2:#ccd0da; --bg3:#bcc0cc;
  --t0:#4c4f69; --t1:#5c5f77; --t2:#6c6f85; --t3:#8c8fa1;
  --grn:#40a02b; --red:#d20f39; --amb:#df8e1d; --cyn:#1e66f5;
  --accent-rgb:64,160,43;
  --border:rgba(76,79,105,.12);
  --border-strong:rgba(76,79,105,.22);
  --surface:rgba(76,79,105,.04);
  --surface-hover:rgba(76,79,105,.08);
  --input-bg:rgba(255,255,255,.6);
  --nav-bg:#e6e9ef;
  --scroll:rgba(76,79,105,.2);
}
body{font-family:var(--f);background:var(--bg);color:var(--t0);overflow:hidden;height:100vh;display:flex;transition:background .3s,color .3s}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(128,128,128,.2);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:rgba(128,128,128,.35)}
select{appearance:none;-webkit-appearance:none}
select option{background:var(--bg2);color:var(--t0)}
input[type=number]::-webkit-inner-spin-button{opacity:.3}

.nav{width:135px;background:var(--nav-bg);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0}
.nav-brand{padding:14px 12px 10px;display:flex;align-items:center;gap:7px}
.nav-sep{height:1px;background:var(--border);margin:0 10px 4px}
.nav-btn{display:flex;align-items:center;gap:8px;width:100%;padding:8px 14px;border:none;cursor:pointer;
  background:transparent;border-left:2px solid transparent;color:var(--t2);
  font:600 10.5px/1 var(--f);letter-spacing:.5px;text-align:left;transition:all .12s}
.nav-btn:hover{color:var(--t0);background:var(--surface)}
.nav-btn.active{color:var(--grn);background:rgba(var(--accent-rgb),.09);border-left-color:var(--grn)}
.nav-btn svg{width:14px;height:14px;flex-shrink:0;opacity:.6}
.nav-btn.active svg{opacity:1}
.nav-badge{margin-left:auto;font-size:8px;font-weight:700;padding:1px 6px;border-radius:5px;background:var(--surface);color:var(--t2)}
.nav-btn.active .nav-badge{background:rgba(var(--accent-rgb),.18);color:var(--grn)}

.content{flex:1;padding:14px 18px;overflow-y:auto;max-height:100vh}
.page-title{font-size:9px;font-weight:700;letter-spacing:2px;color:var(--t3);margin-bottom:12px}
.page{display:none}.page.active{display:flex;flex-direction:column;gap:12px}

.hero{display:flex;align-items:center;gap:18px;padding:12px 16px;border-radius:10px;border:1px solid var(--border);transition:all .5s}
.hero.on{background:linear-gradient(135deg,rgba(var(--accent-rgb),.06) 0%,transparent 60%);border-color:rgba(var(--accent-rgb),.18)}
.hero.busy{background:linear-gradient(135deg,rgba(255,171,0,.05) 0%,transparent 60%);border-color:rgba(255,171,0,.15)}
.hero.off{background:linear-gradient(135deg,rgba(255,82,82,.04) 0%,transparent 60%)}
.hero-status{font-size:12px;font-weight:700;letter-spacing:1.5px;transition:color .3s}
.hero-sub{font-size:10.5px;color:var(--t2);margin-top:3px}
.hero-detail{font-size:9px;color:var(--t3);margin-top:2px}
.btn-go,.btn-stop{padding:7px 18px;border-radius:6px;border:none;cursor:pointer;font:700 10.5px var(--f);letter-spacing:.8px;transition:all .2s;display:flex;align-items:center;gap:5px}
.btn-go{background:linear-gradient(135deg,#00c853,#00e676);color:#000}
.btn-go:disabled{background:var(--surface);color:var(--t3);cursor:default}
.btn-stop{background:linear-gradient(135deg,#c62828,#ff5252);color:#fff}
.btn-stop:disabled{background:var(--surface);color:var(--t3);cursor:default}

.stats{display:flex;gap:6px}
.stat{flex:1;padding:10px 8px;background:var(--surface);border-radius:8px;border:1px solid var(--border);display:flex;flex-direction:column;align-items:center;gap:2px;min-width:0}
.stat-label{font-size:8px;font-weight:700;letter-spacing:1.5px;color:var(--t2)}
.stat-val{font-size:16px;font-weight:700;color:var(--t0);letter-spacing:.3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}
.stat-val.sm{font-size:11px}

.prof-sel{display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--surface);border-radius:6px;border:1px solid var(--border)}
.prof-sel label{font-size:9px;font-weight:700;letter-spacing:1px;color:var(--t2);white-space:nowrap}
.prof-sel select{flex:1;background:var(--input-bg);color:var(--t0);border:1px solid var(--border);border-radius:5px;padding:5px 8px;font:500 11px var(--f);outline:none;cursor:pointer}

.log-box{background:var(--input-bg);border-radius:6px;border:1px solid var(--border);padding:8px 10px;max-height:130px;overflow-y:auto;font-size:9.5px;line-height:16px;color:var(--t2)}
.log-dot{width:5px;height:5px;border-radius:50%;transition:all .3s;display:inline-block}
.log-line{display:flex;gap:8px}
.log-ts{color:var(--t3);min-width:50px}
.log-ok{color:var(--grn)}.log-err{color:var(--red)}.log-warn{color:var(--amb)}.log-info{color:var(--cyn)}

.card{background:var(--surface);border-radius:8px;border:1px solid var(--border);padding:12px 14px;display:flex;flex-direction:column;gap:10px}
.card-title{font-size:9px;font-weight:700;letter-spacing:1.5px;color:var(--t2)}
.card.red{border-color:rgba(255,82,82,.2)}.card.red .card-title{color:var(--red)}
.card.grn{border-color:rgba(var(--accent-rgb),.2)}.card.grn .card-title{color:var(--grn)}

.field{display:flex;flex-direction:column;gap:3px}
.fl{font-size:9px;font-weight:600;letter-spacing:1px;color:var(--t2)}
.sel,.inp,.num{background:var(--input-bg);color:var(--t0);border:1px solid var(--border);border-radius:5px;padding:5px 8px;font:500 11px var(--f);outline:none;width:100%}
.sel:focus,.inp:focus,.num:focus{border-color:var(--cyn)}
textarea.inp{resize:vertical;font-size:10.5px}

.tog{display:flex;align-items:flex-start;gap:10px;cursor:pointer;padding:2px 0}
.tog-track{width:34px;height:18px;border-radius:9px;flex-shrink:0;margin-top:1px;position:relative;background:var(--surface-hover);border:1px solid var(--border);transition:all .2s}
.tog-track.on{background:rgba(var(--accent-rgb),.28);border-color:rgba(var(--accent-rgb),.5)}
.tog-knob{width:12px;height:12px;border-radius:6px;position:absolute;top:2px;left:2px;background:var(--t3);transition:all .2s}
.tog-track.on .tog-knob{left:18px;background:var(--grn);box-shadow:0 0 8px rgba(var(--accent-rgb),.55)}
.tog-label{font-size:11.5px;color:var(--t0)}
.tog-sub{font-size:9.5px;color:var(--t2);margin-top:2px}

.g2{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:6px}

.dropzone{border:2px dashed var(--border-strong);border-radius:8px;padding:16px;text-align:center;cursor:pointer;color:var(--t2);font-size:11px;transition:all .2s}
.dropzone:hover{border-color:rgba(var(--accent-rgb),.4);color:var(--grn);background:rgba(var(--accent-rgb),.05)}

.prof-item{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:7px;cursor:pointer;background:var(--surface);border:1px solid var(--border);transition:all .12s;margin-bottom:4px}
.prof-item:hover{background:var(--surface-hover)}
.prof-item.sel{background:rgba(var(--accent-rgb),.08);border-color:rgba(var(--accent-rgb),.25)}
.prof-dot{width:8px;height:8px;border-radius:4px;background:var(--t3);flex-shrink:0}
.prof-item.sel .prof-dot{background:var(--grn);box-shadow:0 0 6px rgba(var(--accent-rgb),.6)}
.prof-name{font-size:11.5px;font-weight:600;color:var(--t0)}.prof-item.sel .prof-name{color:var(--grn)}
.prof-meta{font-size:9px;color:var(--t2)}
.prof-btn{width:24px;height:24px;border-radius:5px;display:flex;align-items:center;justify-content:center;background:var(--surface);border:1px solid var(--border);cursor:pointer;color:var(--t1);font:600 10px var(--f)}
.prof-btn:hover{background:var(--surface-hover);color:var(--t0)}

.log-btns{display:flex;gap:5px}
.log-btns button{padding:5px 12px;background:var(--surface);border:1px solid var(--border);border-radius:5px;color:var(--t1);cursor:pointer;font:600 10px var(--f)}
.log-btns button:hover{background:var(--surface-hover)}

@keyframes pulse{0%,100%{transform:scale(1);opacity:.3}50%{transform:scale(1.06);opacity:.12}}
@keyframes rspin{from{transform:rotate(0)}to{transform:rotate(360deg)}}
.ring-svg.busy circle.arc{animation:rspin 1.8s linear infinite}
</style>
</head><body>
<div class="nav">
  <div class="nav-brand">
    <svg width="26" height="26" viewBox="0 0 120 120" fill="none">
      <defs><linearGradient id="lg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" id="lga" stop-color="#ff5252"/><stop offset="100%" id="lgb" stop-color="#b71c1c"/></linearGradient></defs>
      <path id="lshield" d="M60 8C85 8 95 12 95 35C95 68 80 95 60 112C40 95 25 68 25 35C25 12 35 8 60 8Z" fill="url(#lg)" stroke="#ff5252" stroke-width="1.5"/>
      <circle cx="60" cy="48" r="10" fill="none" stroke="#fff" stroke-width="2.5" opacity=".85"/>
      <path d="M55 56L55 75Q55 78 58 78L62 78Q65 78 65 75L65 56" fill="none" stroke="#fff" stroke-width="2.5" opacity=".85"/>
      <circle cx="43" cy="38" r="2" fill="#fff" opacity=".35"/><circle cx="77" cy="38" r="2" fill="#fff" opacity=".35"/><circle cx="60" cy="25" r="2" fill="#fff" opacity=".35"/>
    </svg>
    <div><span style="font-size:12px;font-weight:700;color:var(--t0);letter-spacing:2px">VPN</span><span id="brand-t" style="font-size:12px;font-weight:700;color:var(--t3);letter-spacing:2px;transition:color .3s">TRAY</span></div>
  </div>
  <div class="nav-sep"></div>
  <div id="nav-c"></div>
  <div style="flex:1"></div>
  <div style="padding:8px 14px;border-top:1px solid var(--border);font-size:8px;color:var(--t3)">v3.1</div>
</div>
<div class="content"><div class="page-title" id="ptitle">CONNECT</div><div id="pages"></div></div>

<script>
var NAV=[
  {id:'connect',label:'CONNECT',icon:'<path d="M9 0L3 8H7L5 16L13 6H9Z"/>'},
  {id:'profiles',label:'PROFILES',icon:'<path d="M1 4.5H15V14.5H1Z" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M1 4.5V3L6 3L7.5 4.5" fill="none" stroke="currentColor" stroke-width="1.3"/>'},
  {id:'tunnel',label:'TUNNEL',icon:'<g stroke="currentColor" stroke-width="1.3" stroke-linecap="round"><line x1="1" y1="4" x2="15" y2="4"/><line x1="1" y1="8" x2="15" y2="8"/><line x1="1" y1="12" x2="15" y2="12"/><circle cx="5" cy="4" r="1.8" fill="currentColor"/><circle cx="11" cy="8" r="1.8" fill="currentColor"/><circle cx="3" cy="12" r="1.8" fill="currentColor"/></g>'},
  {id:'security',label:'SECURITY',icon:'<path d="M8 1C12 1 14 2 14 5C14 10 12 14 8 15.5C4 14 2 10 2 5C2 2 4 1 8 1Z" fill="none" stroke="currentColor" stroke-width="1.3"/><line x1="8" y1="1" x2="8" y2="15.5" stroke="currentColor" stroke-width="1"/>'},
  {id:'network',label:'NETWORK',icon:'<circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" stroke-width="1.1"/><ellipse cx="8" cy="8" rx="2.8" ry="6.5" fill="none" stroke="currentColor" stroke-width="1.1"/><line x1="1.5" y1="8" x2="14.5" y2="8" stroke="currentColor" stroke-width="1.1"/>'},
  {id:'logs',label:'LOGS',icon:'<g stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><polyline points="2,3 7,8 2,13" fill="none"/><line x1="8" y1="13" x2="14" y2="13"/></g>'},
  {id:'settings',label:'SETTINGS',icon:'<g stroke="currentColor" stroke-width="1.5" stroke-linecap="round" fill="none"><path d="M10 2A5 5 0 0 0 2 7"/><line x1="7" y1="7" x2="14" y2="14"/><line x1="12.5" y1="14" x2="14" y2="12.5"/></g>'}
];
var profiles=[],selP=0,vpnSt='disconnected',vpnProf='';
function br(cmd,data){console.log('BRIDGE:'+cmd+':'+JSON.stringify(data||{}))}
function init(){
  var nc=document.getElementById('nav-c');
  NAV.forEach(function(n){var b=document.createElement('button');b.className='nav-btn'+(n.id==='connect'?' active':'');b.dataset.id=n.id;b.innerHTML='<svg viewBox="0 0 16 16" fill="currentColor">'+n.icon+'</svg>'+n.label+'<span class="nav-badge" id="b-'+n.id+'" style="display:none"></span>';b.onclick=function(){swPage(n.id)};nc.appendChild(b)});
  buildPages();
  swPage('connect');
  setTimeout(function(){br('init')},300);
}
function swPage(id){document.querySelectorAll('.nav-btn').forEach(function(b){b.classList.toggle('active',b.dataset.id===id)});document.querySelectorAll('.page').forEach(function(p){p.classList.toggle('active',p.id==='p-'+id)});document.getElementById('ptitle').textContent=id.toUpperCase()}

// python callbacks
function onProfiles(list){profiles=list;renderProfs()}
function onSettings(s){
  if(s.auto_connect)togOn('ov-autocon');
  if(s.dns_fix!==false)togOn('ov-dns');
  if(s.killswitch)togOn('ov-ks');
  if(s.reconnect!==false)togOn('ov-recon');
  var rd=document.getElementById('ov-rd');if(rd&&s.reconnect_delay)rd.value=s.reconnect_delay;
  var theme=s.theme||'tactical';
  applyTheme(theme);
  var t=document.getElementById('ov-theme');if(t)t.value=theme;
}
function onVersion(v){var e=document.getElementById('sys-info');if(e)e.innerHTML=esc(v)+'<br>~/.vpntray/profiles/ &middot; ~/.vpntray/logs/'}

// themed confirm/prompt replacing browser alert/prompt
function modalConfirm(msg,cb){
  var o=document.createElement('div');
  o.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;z-index:1000';
  o.innerHTML='<div style="background:var(--bg1);border:1px solid var(--border-strong);border-radius:10px;padding:18px 20px;min-width:300px"><div style="font-size:12px;color:var(--t0);margin-bottom:16px" id="mc-msg"></div><div style="display:flex;gap:6px;justify-content:flex-end"><button id="mc-no" style="padding:6px 14px;background:var(--surface-hover);border:1px solid var(--border);border-radius:5px;color:var(--t1);font:600 10px var(--f);cursor:pointer">Cancel</button><button id="mc-yes" style="padding:6px 14px;background:rgba(255,82,82,.15);border:1px solid rgba(255,82,82,.35);border-radius:5px;color:var(--red);font:600 10px var(--f);cursor:pointer">OK</button></div></div>';
  document.body.appendChild(o);
  document.getElementById('mc-msg').textContent=msg;
  var close=function(v){o.remove();cb(v)};
  document.getElementById('mc-yes').onclick=function(){close(true)};
  document.getElementById('mc-no').onclick=function(){close(false)};
}
function modalPrompt(msg,def,cb){
  var o=document.createElement('div');
  o.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;z-index:1000';
  o.innerHTML='<div style="background:var(--bg1);border:1px solid var(--border-strong);border-radius:10px;padding:18px 20px;min-width:340px"><div style="font-size:12px;color:var(--t0);margin-bottom:12px" id="mp-msg"></div><input id="mp-in" class="inp" style="margin-bottom:14px"><div style="display:flex;gap:6px;justify-content:flex-end"><button id="mp-no" style="padding:6px 14px;background:var(--surface-hover);border:1px solid var(--border);border-radius:5px;color:var(--t1);font:600 10px var(--f);cursor:pointer">Cancel</button><button id="mp-yes" style="padding:6px 14px;background:rgba(var(--accent-rgb),.18);border:1px solid rgba(var(--accent-rgb),.35);border-radius:5px;color:var(--grn);font:600 10px var(--f);cursor:pointer">OK</button></div></div>';
  document.body.appendChild(o);
  document.getElementById('mp-msg').textContent=msg;
  var inp=document.getElementById('mp-in');inp.value=def||'';setTimeout(function(){inp.focus();inp.select()},50);
  var close=function(v){o.remove();cb(v)};
  document.getElementById('mp-yes').onclick=function(){close(inp.value)};
  document.getElementById('mp-no').onclick=function(){close(null)};
  inp.addEventListener('keydown',function(e){if(e.key==='Enter')close(inp.value);else if(e.key==='Escape')close(null)});
}

function onConfig(txt){
  var overlay=document.createElement('div');
  overlay.id='cfg-modal';
  overlay.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;z-index:1000;padding:20px';
  overlay.innerHTML='<div style="background:var(--bg1);border:1px solid var(--border-strong);border-radius:10px;width:90%;max-width:700px;max-height:80vh;display:flex;flex-direction:column;overflow:hidden"><div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center"><span style="font-size:10px;font-weight:700;letter-spacing:2px;color:var(--cyn)">CONFIG</span><div style="display:flex;gap:6px"><button id="cfg-copy" style="padding:4px 10px;background:var(--surface-hover);border:1px solid var(--border);border-radius:4px;color:var(--t1);font:600 10px var(--f);cursor:pointer">Copy</button><button id="cfg-close" style="padding:4px 10px;background:rgba(255,82,82,.12);border:1px solid rgba(255,82,82,.25);border-radius:4px;color:var(--red);font:600 10px var(--f);cursor:pointer">Close</button></div></div><pre id="cfg-body" style="margin:0;padding:14px 16px;overflow:auto;font:500 11px var(--f);color:var(--t1);white-space:pre-wrap;word-break:break-all;flex:1"></pre></div>';
  document.body.appendChild(overlay);
  document.getElementById('cfg-body').textContent=txt;
  var close=function(){var m=document.getElementById('cfg-modal');if(m)m.remove();document.removeEventListener('keydown',onkey)};
  var onkey=function(e){if(e.key==='Escape')close()};
  document.getElementById('cfg-close').onclick=close;
  document.getElementById('cfg-copy').onclick=function(){navigator.clipboard.writeText(txt)};
  overlay.onclick=function(e){if(e.target===overlay)close()};
  document.addEventListener('keydown',onkey);
}
function onStatus(st,prof){vpnSt=st;vpnProf=prof;updateUI()}
function onStats(d){
  var fb=function(b){if(b<1024)return b+'B';if(b<1048576)return(b/1024).toFixed(1)+'K';if(b<1073741824)return(b/1048576).toFixed(1)+'M';return(b/1073741824).toFixed(2)+'G'};
  var s=function(id){return document.getElementById(id)};
  if(s('s-dl'))s('s-dl').textContent=fb(d.bytes_in||0);
  if(s('s-ul'))s('s-ul').textContent=fb(d.bytes_out||0);
  if(s('s-ip'))s('s-ip').textContent=d.local_ip||'--';
  if(s('s-rip'))s('s-rip').textContent=d.remote_ip||'--';
}
function togOn(id){var cb=document.getElementById(id);if(cb){cb.checked=true;var t=cb.closest('.tog');if(t)t.querySelector('.tog-track').classList.add('on')}}

function applyTheme(name){
  if(name==='tactical')document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme',name);
}

function renderProfs(){
  var sel=document.getElementById('prof-combo');
  if(sel){sel.innerHTML='';profiles.forEach(function(p,i){var o=document.createElement('option');o.value=i;o.textContent=p.name+' \u2014 '+p.file;sel.appendChild(o)});if(selP<profiles.length)sel.value=selP}
  var list=document.getElementById('prof-list');
  if(!list)return;
  list.innerHTML='';
  profiles.forEach(function(p,i){
    var d=document.createElement('div');
    d.className='prof-item'+(i===selP?' sel':'');
    d.innerHTML='<div class="prof-dot"></div><div style="flex:1"><div class="prof-name"></div><div class="prof-meta"></div></div><div class="prof-actions" style="display:flex;gap:4px"><div class="prof-btn" data-act="view" title="View">V</div><div class="prof-btn" data-act="dup" title="Duplicate">D</div><div class="prof-btn" data-act="rm" title="Remove">X</div></div>';
    // set text via textContent so special chars can't break anything
    d.querySelector('.prof-name').textContent=p.name;
    d.querySelector('.prof-meta').textContent=p.file;
    d.querySelectorAll('.prof-btn').forEach(function(btn){
      btn.addEventListener('click',function(e){
        e.stopPropagation();
        var act=btn.dataset.act;
        if(act==='view')br('getConfig',{name:p.name});
        else if(act==='dup')modalPrompt('New profile name:',p.name+'_copy',function(nn){if(nn)br('duplicate',{name:p.name,new_name:nn})});
        else if(act==='rm')modalConfirm('Remove profile "'+p.name+'"?',function(ok){if(ok)br('remove',{name:p.name})});
      });
    });
    d.addEventListener('click',function(){selP=i;renderProfs()});
    list.appendChild(d);
  });
  badge('profiles',profiles.length);
}

function doGo(){
  if(!profiles.length)return;
  gatherOv();
  var p=profiles[selP];
  br('connect',{path:p.path,name:p.name});
}
function doStop(){br('disconnect')}

function gatherOv(){
  var g=function(v){var e=document.getElementById(v);return e?(e.type==='checkbox'?e.checked:e.value):''};
  var n=function(v){var e=document.getElementById(v);return e&&e.value?parseInt(e.value):null};
  br('setOverrides',{
    proto:g('ov-proto'),cipher:g('ov-cipher'),auth:g('ov-auth'),compress:g('ov-comp'),
    dev_type:g('ov-dev'),tls_version_min:g('ov-tls'),verbosity:g('ov-verb'),redirect_gw:g('ov-rg'),
    tun_mtu:n('ov-mtu'),fragment:n('ov-frag'),mssfix:n('ov-mss'),port:n('ov-port'),
    keepalive_interval:n('ov-ki'),keepalive_timeout:n('ov-kt'),ping:n('ov-ping'),ping_restart:n('ov-pr'),
    reneg_sec:n('ov-reneg'),sndbuf:n('ov-sndbuf'),rcvbuf:n('ov-rcvbuf'),txqueuelen:n('ov-txq'),
    float:g('ov-float'),nobind:g('ov-nobind'),killswitch:g('ov-ks'),dns_fix:g('ov-dns'),
    auth_user_pass:g('ov-authfile'),pull_filter:g('ov-pf'),
    proxy_type:g('ov-px'),proxy_host:g('ov-pxh'),proxy_port:n('ov-pxp'),proxy_auth_file:g('ov-pxa'),
    route_nopull:g('ov-rnp'),custom_routes:g('ov-routes'),
    reconnect:g('ov-recon'),reconnect_delay:n('ov-rd')||5,extra_directives:g('ov-extra')
  });
}

function appendLog(text){
  var cls=text.indexOf('Completed')>-1||text.indexOf('[+]')>-1?'log-ok':text.indexOf('[!]')>-1||text.indexOf('Error')>-1||text.indexOf('AUTH_FAILED')>-1?'log-err':text.indexOf('[*]')>-1||text.indexOf('WARNING')>-1?'log-warn':text.indexOf('VERIFY')>-1||text.indexOf('PUSH')>-1||text.indexOf('TLS')>-1?'log-info':'';
  var m=text.match(/^\[(\d{2}:\d{2}:\d{2})\]\s?(.*)$/);
  var ts=m?m[1]:'';
  var body=m?m[2]:text;
  var html='<div class="log-line"><span class="log-ts">'+ts+'</span><span class="'+cls+'">'+esc(body)+'</span></div>';
  ['log-prev','log-full'].forEach(function(id){
    var el=document.getElementById(id);
    if(!el)return;
    el.insertAdjacentHTML('beforeend',html);
    // cap at 1000 lines to keep the dom light
    var cap=id==='log-prev'?200:1000;
    while(el.children.length>cap)el.removeChild(el.firstChild);
    el.scrollTop=el.scrollHeight;
  });
}
function setUptime(t){var e=document.getElementById('s-up');if(e)e.textContent=t}

function updateUI(){
  var on=vpnSt==='connected',busy=vpnSt==='connecting'||vpnSt==='reconnecting';
  var hero=document.getElementById('hero');hero.className='hero '+(on?'on':busy?'busy':'off');
  var st=document.getElementById('hero-st');st.textContent=on?'CONNECTED':busy?(vpnSt==='reconnecting'?'RECONNECTING...':'CONNECTING...'):'DISCONNECTED';
  st.style.color=on?'var(--grn)':busy?'var(--amb)':'var(--red)';
  document.getElementById('hero-sub').textContent=on?vpnProf:'No active tunnel';
  document.getElementById('hero-det').style.display=on?'block':'none';
  document.getElementById('btn-go').disabled=on||busy;
  document.getElementById('btn-stop').disabled=!on&&!busy;
  var arc=document.getElementById('ring-arc');arc.style.stroke=on?'var(--grn)':busy?'var(--amb)':'var(--red)';arc.setAttribute('stroke-dashoffset',on?'0':busy?'103':'190');
  document.getElementById('ring-svg').className='ring-svg'+(busy?' busy':'');
  var ro=document.getElementById('ring-out');ro.style.border='1.5px solid '+(on?'var(--grn)':busy?'var(--amb)':'transparent');ro.style.animation=on?'pulse 3s ease infinite':busy?'pulse 1.4s ease infinite':'none';
  document.getElementById('lga').setAttribute('stop-color',on?'#00e676':'#ff5252');document.getElementById('lgb').setAttribute('stop-color',on?'#00a152':'#b71c1c');
  document.getElementById('lshield').setAttribute('stroke',on?'#00e676':'#ff5252');
  document.getElementById('brand-t').style.color=on?'var(--grn)':'var(--t3)';
  var dot=document.getElementById('log-dot');if(dot){dot.style.background=on?'var(--grn)':'var(--red)';dot.style.boxShadow=on?'0 0 6px rgba(0,230,118,.6)':'none'}
  badge('connect',on?'ON':null);
  if(vpnSt==='disconnected'){['s-up','s-dl','s-ul','s-ip','s-rip'].forEach(function(id){var e=document.getElementById(id);if(e)e.textContent='--'})}
}
function badge(id,val){var b=document.getElementById('b-'+id);if(b){if(val!=null){b.style.display='';b.textContent=val}else b.style.display='none'}}
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function mkTog(id,on,label,sub){return '<div class="tog" onclick="var cb=document.getElementById(\''+id+'\');cb.checked=!cb.checked;this.querySelector(\'.tog-track\').classList.toggle(\'on\')"><input type="checkbox" id="'+id+'" '+(on?'checked':'')+' style="display:none"><div class="tog-track'+(on?' on':'')+'"><div class="tog-knob"></div></div><div><div class="tog-label">'+label+'</div>'+(sub?'<div class="tog-sub">'+sub+'</div>':'')+'</div></div>'}
function mkF(l,h){return '<div class="field"><span class="fl">'+l+'</span>'+h+'</div>'}
function mkS(id,o){return '<select class="sel" id="'+id+'">'+o.map(function(v){return '<option>'+v+'</option>'}).join('')+'</select>'}
function mkN(id,p){return '<input type="number" class="num" id="'+id+'" placeholder="'+(p||'--')+'">'}

function buildPages(){
  document.getElementById('pages').innerHTML=
  '<div class="page active" id="p-connect">'+
    '<div class="hero off" id="hero"><div style="position:relative;width:80px;height:80px;display:flex;align-items:center;justify-content:center"><div id="ring-out" style="position:absolute;inset:0;border-radius:50%"></div><svg width="74" height="74" viewBox="0 0 74 74" class="ring-svg" id="ring-svg" style="position:absolute"><circle cx="37" cy="37" r="34" fill="none" stroke="var(--border-strong)" stroke-width="1.5"/><circle class="arc" id="ring-arc" cx="37" cy="37" r="34" fill="none" stroke="var(--red)" stroke-width="2" stroke-dasharray="213" stroke-dashoffset="190" stroke-linecap="round" opacity=".6" style="transition:all 1s cubic-bezier(.4,0,.2,1)"/></svg><svg width="40" height="40" viewBox="0 0 120 120" fill="none" style="position:relative;z-index:1"><path d="M60 8C85 8 95 12 95 35C95 68 80 95 60 112C40 95 25 68 25 35C25 12 35 8 60 8Z" fill="url(#lg)" stroke="var(--red)" stroke-width="1.5"/><circle cx="60" cy="48" r="10" fill="none" stroke="#fff" stroke-width="2.5" opacity=".85"/><path d="M55 56L55 75Q55 78 58 78L62 78Q65 78 65 75L65 56" fill="none" stroke="#fff" stroke-width="2.5" opacity=".85"/></svg></div>'+
    '<div style="flex:1;min-width:0"><div class="hero-status" id="hero-st" style="color:var(--red)">DISCONNECTED</div><div class="hero-sub" id="hero-sub">No active tunnel</div><div class="hero-detail" id="hero-det" style="display:none">AES-256-GCM &middot; TLSv1.3 &middot; tun0</div></div>'+
    '<div style="display:flex;flex-direction:column;gap:6px"><button class="btn-go" id="btn-go" onclick="doGo()"><svg width="9" height="11" viewBox="0 0 384 512" fill="#000"><path d="M73 39c-14.8-9.1-33.4-9.4-48.5-.9S0 62.6 0 80V432c0 17.4 9.4 33.4 24.5 41.9s33.7 8.1 48.5-.9L361 297c14.3-8.8 23-24.2 23-41s-8.7-32.2-23-41L73 39z"/></svg>CONNECT</button><button class="btn-stop" id="btn-stop" disabled onclick="doStop()"><svg width="9" height="9" viewBox="0 0 448 512" fill="#fff"><path d="M0 128C0 92.7 28.7 64 64 64H384c35.3 0 64 28.7 64 64V384c0 35.3-28.7 64-64 64H64c-35.3 0-64-28.7-64-64V128z"/></svg>STOP</button></div></div>'+
    '<div class="stats"><div class="stat"><span class="stat-label">UPTIME</span><span class="stat-val" id="s-up">--</span></div><div class="stat"><span class="stat-label">&darr; DOWN</span><span class="stat-val" id="s-dl">--</span></div><div class="stat"><span class="stat-label">&uarr; UP</span><span class="stat-val" id="s-ul">--</span></div><div class="stat"><span class="stat-label">TUN IP</span><span class="stat-val sm" id="s-ip">--</span></div><div class="stat"><span class="stat-label">REMOTE</span><span class="stat-val sm" id="s-rip">--</span></div></div>'+
    '<div class="prof-sel"><label>PROFILE</label><select id="prof-combo" onchange="selP=+this.value"></select></div>'+
    '<div><div style="display:flex;align-items:center;gap:5px;margin-bottom:5px"><div class="log-dot" id="log-dot" style="background:var(--red)"></div><span style="font-size:8px;color:var(--t2);font-weight:700;letter-spacing:1.5px">LIVE</span></div><div class="log-box" id="log-prev"></div></div>'+
  '</div>'+

  '<div class="page" id="p-profiles"><div class="dropzone" onclick="br(\'import\')">Drop .ovpn files here &mdash; or click to browse</div><div id="prof-list"></div></div>'+

  '<div class="page" id="p-tunnel"><div style="font-size:10px;color:var(--t2)">Override .ovpn config per-connection</div>'+
    '<div class="card"><div class="card-title">PROTOCOL & ENCRYPTION</div><div class="g3">'+mkF('PROTOCOL',mkS('ov-proto',['(default)','udp','tcp','udp4','tcp4','udp6','tcp6']))+mkF('CIPHER',mkS('ov-cipher',['(default)','AES-256-GCM','AES-128-GCM','CHACHA20-POLY1305','AES-256-CBC','AES-128-CBC','BF-CBC','NONE']))+mkF('AUTH',mkS('ov-auth',['(default)','SHA256','SHA384','SHA512','SHA1','MD5','NONE']))+mkF('COMPRESS',mkS('ov-comp',['(none)','lzo','lz4','lz4-v2','stub','migrate']))+mkF('DEVICE',mkS('ov-dev',['(default)','tun','tap']))+mkF('TLS MIN',mkS('ov-tls',['(default)','1.0','1.1','1.2','1.3']))+'</div></div>'+
    '<div class="card"><div class="card-title">TUNING</div><div class="g4">'+['MTU:ov-mtu','Frag:ov-frag','MSSFix:ov-mss','Port:ov-port','KA Int:ov-ki','KA To:ov-kt','Ping:ov-ping','Ping-rst:ov-pr','Reneg:ov-reneg','Sndbuf:ov-sndbuf','Rcvbuf:ov-rcvbuf','TXQ:ov-txq'].map(function(s){var p=s.split(':');return mkF(p[0],mkN(p[1]))}).join('')+'</div></div>'+
    '<div class="card"><div class="card-title">BEHAVIOR</div><div class="g2">'+mkF('VERBOSITY',mkS('ov-verb',['0','1','2','3','4','5','6','7','8','9','11']))+mkF('REDIRECT GW',mkS('ov-rg',['(default)','def1','def1 bypass-dhcp','local','autolocal','def1 block-local']))+'</div><div style="display:flex;gap:18px;margin-top:6px">'+mkTog('ov-float',false,'--float','')+mkTog('ov-nobind',true,'--nobind','')+mkTog('ov-ptun',true,'--persist-tun','')+'</div></div>'+
  '</div>'+

  '<div class="page" id="p-security">'+
    '<div class="card red"><div class="card-title">KILL SWITCH</div>'+mkTog('ov-ks',false,'Block all traffic if VPN drops','iptables rules. LAN stays accessible.')+'</div>'+
    '<div class="card grn"><div class="card-title">DNS</div>'+mkTog('ov-dns',true,'DNS leak prevention','update-resolv-conf')+'</div>'+
    '<div class="card"><div class="card-title">AUTH</div>'+mkF('AUTH FILE','<div style="display:flex;gap:4px"><input class="inp" id="ov-authfile" placeholder="/path/to/auth.txt" style="flex:1"><button class="prof-btn" style="width:30px;height:auto" onclick="br(\'browseAuth\')">...</button></div>')+'</div>'+
    '<div class="card"><div class="card-title">PULL FILTERS</div><textarea class="inp" id="ov-pf" rows="2" placeholder=\'ignore "dhcp-option"\'></textarea></div>'+
  '</div>'+

  '<div class="page" id="p-network">'+
    '<div class="card"><div class="card-title">PROXY</div><div style="display:grid;grid-template-columns:100px 1fr 80px;gap:6px">'+mkF('TYPE',mkS('ov-px',['(none)','http','socks5']))+mkF('HOST','<input class="inp" id="ov-pxh" placeholder="proxy.example.com">')+mkF('PORT',mkN('ov-pxp','8080'))+'</div><input class="inp" id="ov-pxa" placeholder="Proxy auth file" style="margin-top:8px"></div>'+
    '<div class="card"><div class="card-title">ROUTING</div>'+mkTog('ov-rnp',false,'Ignore server-pushed routes','--route-nopull')+mkF('CUSTOM ROUTES','<textarea class="inp" id="ov-routes" rows="2" placeholder="10.8.0.0 255.255.255.0"></textarea>')+'</div>'+
  '</div>'+

  '<div class="page" id="p-logs"><div class="log-box" id="log-full" style="flex:1;max-height:none;min-height:320px"></div><div class="log-btns"><button onclick="document.getElementById(\'log-full\').innerHTML=\'\'">Clear</button><button onclick="navigator.clipboard.writeText(document.getElementById(\'log-full\').innerText)">Copy</button><button onclick="br(\'openLogDir\')">Open Dir</button><button onclick="br(\'fetchMgmt\')">Mgmt Log</button></div></div>'+

  '<div class="page" id="p-settings">'+
    '<div class="card"><div class="card-title">APPEARANCE</div>'+
      '<div class="field"><span class="fl">THEME</span>'+
      '<select class="sel" id="ov-theme" onchange="applyTheme(this.value);br(\'setOverrides\',{theme:this.value})">'+
        '<option value="tactical">Tactical (dark, high contrast)</option>'+
        '<option value="mocha">Catppuccin Mocha (soft dark)</option>'+
        '<option value="latte">Catppuccin Latte (light)</option>'+
      '</select></div>'+
    '</div>'+
    '<div class="card"><div class="card-title">STARTUP</div>'+mkTog('ov-autocon',false,'Auto-connect last profile on login','')+mkTog('ov-recon',true,'Auto-reconnect on drop','')+'<div style="display:flex;align-items:center;gap:8px;margin-left:44px"><span style="font-size:10px;color:var(--t2)">Delay:</span><input type="number" class="num" id="ov-rd" value="5" style="width:50px;text-align:center"><span style="font-size:10px;color:var(--t2)">sec</span></div></div>'+
    '<div class="card"><div class="card-title">EXTRA DIRECTIVES</div><textarea class="inp" id="ov-extra" rows="3" placeholder="--sndbuf 393216"></textarea></div>'+
    '<div class="card"><div class="card-title">SYSTEM</div><div id="sys-info" style="font-size:10px;color:var(--t2);line-height:17px">Loading...</div></div>'+
  '</div>';

  setTimeout(function(){var v=document.getElementById('ov-verb');if(v)v.value='3'},200);
}
document.addEventListener('DOMContentLoaded',init);
</script></body></html>"""


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] vpntray needs root for openvpn. run: sudo python3 vpntray.py")
        sys.exit(1)
    VPNTrayApp().run()
