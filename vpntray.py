#!/usr/bin/env python3
# vpntray - openvpn tray client for kali


import sys, os, signal, json, shutil, subprocess, socket, secrets, re
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
    QLinearGradient, QPainterPath
)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal, QUrl, QPoint
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage, QWebEngineSettings, QWebEngineProfile

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

ICON_DIR = Path("/opt/vpntray/icons")
if not ICON_DIR.exists():
    ICON_DIR = Path(__file__).parent / "icons"

def load_icon(state):
    """state in ('on','off','busy'). Returns QIcon."""
    svg = ICON_DIR / f"vpntray-{state}.svg"
    if svg.exists(): return QIcon(str(svg))
    png = ICON_DIR / f"vpntray-{state}-64.png"
    if png.exists(): return QIcon(str(png))
    return _paint_fallback(state)


def _paint_fallback(state):
    # sodium amber for connected, red for off, warning amber for busy
    colors = {"on": "#FFB347", "off": "#f87171", "busy": "#fbbf24"}
    symbols = {"on": "check", "off": "x", "busy": "dots"}
    color = colors.get(state, "#f87171")
    sym = symbols.get(state, "x")
    sz = 64
    pm = QPixmap(sz, sz); pm.fill(Qt.transparent)
    p = QPainter(pm); p.setRenderHint(QPainter.Antialiasing)

    shield = QPainterPath()
    cx, t, b, w = sz/2, 4, sz-4, sz-8
    shield.moveTo(cx, t)
    shield.cubicTo(cx+w*0.52, t, cx+w*0.52, (t+b)*0.42, cx, b)
    shield.cubicTo(cx-w*0.52, (t+b)*0.42, cx-w*0.52, t, cx, t)

    grad = QLinearGradient(0, 0, 0, sz)
    qc = QColor(color)
    grad.setColorAt(0, qc.lighter(140))
    grad.setColorAt(1, qc.darker(140))
    p.setBrush(QBrush(grad))
    p.setPen(QPen(qc.lighter(110), 1.5))
    p.drawPath(shield)

    p.setPen(QPen(QColor("#1a0f00" if state == "on" else "#fff"), 3.5, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    if sym == "check":
        p.drawLine(21, 34, 28, 42); p.drawLine(28, 42, 43, 24)
    elif sym == "dots":
        p.setPen(Qt.NoPen); p.setBrush(QColor("#fff"))
        for x in (24, 32, 40): p.drawEllipse(QPoint(x, 33), 2, 2)
    else:
        p.drawLine(23, 24, 41, 42); p.drawLine(41, 24, 23, 42)
    p.end()
    return QIcon(pm)


# -- state --

DEFAULTS = {
    "last_profile": None, "auto_connect": False, "dns_fix": True,
    "killswitch": False, "reconnect": True, "reconnect_delay": 5,
    "theme": "dark",
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
    # filter out anything not in DEFAULTS so legacy junk (theme, etc.) doesn't accumulate
    clean = {k: s.get(k, v) for k, v in DEFAULTS.items()}
    if "last_profile" in s: clean["last_profile"] = s["last_profile"]
    STATE_FILE.write_text(json.dumps(clean, indent=2))


# -- mgmt interface --

class MgmtClient:
    def __init__(self):
        self._sock = None

    def _ensure(self):
        if self._sock: return True
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
        if not self._ensure(): return ""
        try:
            self._sock.sendall((cmd + "\r\n").encode())
            buf = b""
            while True:
                try:
                    chunk = self._sock.recv(4096)
                    if not chunk: self.close(); break
                    buf += chunk
                    if b"END\r\n" in buf or b"SUCCESS" in buf or b"ERROR" in buf:
                        break
                except socket.timeout:
                    self.close(); break
            return buf.decode(errors="replace")
        except:
            self.close(); return ""

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
            for line in self._query("status 2").split("\n"):
                if line.startswith("HEADER,") or not line.strip(): continue
                if "tun" in line or "tap" in line:
                    for word in line.replace(",", " ").split():
                        if (word.startswith("tun") or word.startswith("tap")) and word[3:].isdigit():
                            info["tun_dev"] = word; break
        except Exception:
            pass
        return info

    def fetch_log(self, n=100):
        return self._query(f"log {n}")


# -- ping worker --
# UI shows a latency sparkline; we measure RTT to the remote IP via plain ping
# in a worker thread. one ping every 2s is enough to feed the chart and avoids
# blocking the qt main thread on subprocess.run.

class PingWorker(QThread):
    measured = pyqtSignal(float)  # ms, or -1 on failure

    def __init__(self):
        super().__init__()
        self._stop = False
        self._target = None
        self._rx = re.compile(r"time=([\d.]+)\s*ms")

    def set_target(self, ip):
        self._target = ip

    def stop(self):
        self._stop = True

    def run(self):
        while not self._stop:
            target = self._target
            if not target:
                self.msleep(500); continue
            try:
                r = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", target],
                    capture_output=True, text=True, timeout=2,
                )
                if r.returncode == 0:
                    m = self._rx.search(r.stdout)
                    self.measured.emit(float(m.group(1)) if m else -1)
                else:
                    self.measured.emit(-1)
            except Exception:
                self.measured.emit(-1)
            # 2s cadence — matches the sparkline's "live" feel without flooding
            for _ in range(20):
                if self._stop: return
                self.msleep(100)


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
    tun_detected = pyqtSignal(str)

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
        pw.write_text(MGMT_PASS); pw.chmod(0o600)

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
                          ("sndbuf","--sndbuf"),("rcvbuf","--rcvbuf"),("txqueuelen","--txqueuelen")]:
            v = o.get(key)
            if v: cmd += [flag, str(v)]

        reneg = o.get("reneg_sec")
        if reneg is not None and reneg != "":
            cmd += ["--reneg-sec", str(reneg)]

        ki, kt = o.get("keepalive_interval"), o.get("keepalive_timeout")
        if ki and kt: cmd += ["--keepalive", str(ki), str(kt)]

        # the new ui sends "" for unset selects, treat that as "(none)" so we
        # don't pass `--compress` with no argument (openvpn rejects it as
        # "bad comp option:"). same idea for verbosity and redirect_gw below.
        comp = o.get("compress") or "(none)"
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

        rg = o.get("redirect_gw") or "(default)"
        if rg != "(default)": cmd += ["--redirect-gateway"] + rg.split()

        verb = str(o.get("verbosity") or "3")
        cmd += ["--verb", verb, "--persist-tun"]
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
                                self.tun_detected.emit(word); break
            self._proc.wait()
        except FileNotFoundError:
            self.log_line.emit("[!] openvpn not found"); self.vpn_status.emit("error")
        except Exception as e:
            self.log_line.emit(f"[!] {e}"); self.vpn_status.emit("error")
        finally:
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


# js -> python via console.log('BRIDGE:cmd:json'). avoids QWebChannel which
# needs python3-pyqt5.qtwebchannel and breaks silently if the qrc resource
# can't load. python -> js is just runJavaScript().

class BridgePage(QWebEnginePage):
    def __init__(self, app, profile, parent=None):
        super().__init__(profile, parent)
        self.app = app

    def javaScriptConsoleMessage(self, level, message, line, source):
        if not message.startswith("BRIDGE:"): return
        parts = message.split(":", 2)
        cmd = parts[1] if len(parts) > 1 else ""
        raw = parts[2] if len(parts) > 2 else "{}"
        try: data = json.loads(raw)
        except: data = {}
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
        self._tun_dev = "tun0"
        self._overrides = {}
        self._log_buffer = []
        self._page_ready = False
        # throughput rate calculation needs the previous snapshot
        self._last_bytes_in = 0
        self._last_bytes_out = 0
        self._last_poll_ts = None
        self._latency_ms = -1.0

        # tray
        self.tray = QSystemTrayIcon()
        self._set_tray("disconnected")
        self.tray.setToolTip("VPNTray - Disconnected")
        self.tray.activated.connect(lambda r: self.show_dash() if r == QSystemTrayIcon.Trigger else None)

        # menu
        self.menu = QMenu()
        self.status_act = QAction("Disconnected"); self.status_act.setEnabled(False)
        self.menu.addAction(self.status_act)
        self.menu.addSeparator()
        self.qc_menu = self.menu.addMenu("Quick Connect"); self._build_qc()
        self.dc_act = QAction("Disconnect"); self.dc_act.triggered.connect(self.do_disconnect); self.dc_act.setEnabled(False)
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
        self.win.setWindowIcon(load_icon("off"))
        self.win.setMinimumSize(1080, 680)
        # match the dashboard bg so there's no flash before the html loads
        self.win.setStyleSheet("background: #0a0e1a;")
        lay = QVBoxLayout(self.win); lay.setContentsMargins(0,0,0,0)

        # off-the-record profile -- no disk-backed cookie/cache db. fixes the
        # chromium "database is locked" spam that happens when another qtwebengine
        # app (or a stale root-owned default profile from a previous crash) holds
        # the cookie sqlite open. we don't need cookies for a local html page.
        self.web_profile = QWebEngineProfile(parent=self.win)
        self.web_profile.setHttpCacheType(QWebEngineProfile.MemoryHttpCache)
        self.web_profile.setPersistentCookiesPolicy(QWebEngineProfile.NoPersistentCookies)
        self.page = BridgePage(self, self.web_profile)
        self.page.settings().setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, True)
        self.web = QWebEngineView(); self.web.setPage(self.page)
        self.web.setHtml(HTML, QUrl("about:blank"))
        lay.addWidget(self.web)

        # poll mgmt at 1s for live sparklines (was 5s in v3.1)
        self._poll_t = QTimer(); self._poll_t.timeout.connect(self._poll); self._poll_t.start(1000)

        # ping worker for latency sparkline
        self.ping = PingWorker()
        self.ping.measured.connect(self._on_latency)
        self.ping.start()

        # auto-connect
        if self.state.get("auto_connect") and self.state.get("last_profile"):
            name = self.state["last_profile"]
            for ext in (".ovpn", ".conf"):
                cfg = CONF_DIR / f"{name}{ext}"
                if cfg.exists():
                    QTimer.singleShot(2000, lambda c=str(cfg), n=name: self.do_connect(c, n, {}))
                    break

    # -- bridge handler --

    def handle_bridge(self, cmd, data):
        if cmd == "connect":
            self.do_connect(data["path"], data["name"], self._overrides)
        elif cmd == "disconnect":
            self.do_disconnect()
        elif cmd == "setOverrides":
            app_keys = ("auto_connect", "reconnect", "reconnect_delay", "dns_fix", "killswitch", "theme")
            dirty = False
            for k in app_keys:
                if k in data and self.state.get(k) != data[k]:
                    self.state[k] = data[k]; dirty = True
            if dirty: save_state(self.state)
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
            self._push_profiles(); self._build_qc()
        elif cmd == "openLogDir":
            subprocess.Popen(["xdg-open", str(LOG_DIR)])
        elif cmd == "fetchMgmt":
            log = self.mgmt.fetch_log(100) or "not reachable"
            for line in log.split("\n"):
                line = line.strip()
                if line and not line.startswith("END") and not line.startswith("SUCCESS"):
                    self._push_log(f"[mgmt] {line}")
        elif cmd == "browseAuth":
            p, _ = QFileDialog.getOpenFileName(None, "Auth file")
            if p: self._js(f"document.getElementById('ov-authfile').value={json.dumps(p)};app.gatherOv&&app.gatherOv()")
        elif cmd == "submitAuth":
            pc = getattr(self, "_pending_connect", None)
            self._pending_connect = None
            if not pc: return
            config, name, overrides = pc
            user = (data.get("username") or "").strip()
            passw = data.get("password") or ""
            if not user:
                self._push_log("[!] Auth cancelled -- no username provided")
                self._set_status("disconnected"); return
            cp = self._creds_path(name)
            try:
                cp.write_text(f"{user}\n{passw}\n"); cp.chmod(0o600)
            except Exception as e:
                self._push_log(f"[!] Could not write credentials file: {e}")
                self._set_status("disconnected"); return
            if not data.get("remember", False):
                self._tmp_creds = cp
            overrides["auth_user_pass"] = str(cp)
            self._start_connect(config, name, overrides)
        elif cmd == "cancelAuth":
            self._pending_connect = None
            self._push_log("[*] Connection cancelled")
            self._set_status("disconnected")
        elif cmd == "forgetAuth":
            cp = self._creds_path(data.get("name", ""))
            try:
                if cp.exists():
                    cp.unlink()
                    self._push_log(f"[*] Forgot saved credentials for {data.get('name','')}")
            except Exception as e:
                self._push_log(f"[!] Could not remove credentials: {e}")
        elif cmd == "saveSettings":
            self.state.update(data); save_state(self.state)
        elif cmd == "getSettings":
            self._js(f"onSettings({json.dumps(self.state)})")
        elif cmd == "getVersion":
            self._js(f"onVersion({json.dumps(self._openvpn_version())})")
        elif cmd == "init":
            self._page_ready = True
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
        self._build_qc()

    def _do_import(self):
        paths, _ = QFileDialog.getOpenFileNames(None, "Import Profiles", "",
                                                 "OpenVPN (*.ovpn *.conf);;All (*)")
        for src_path in paths:
            src = Path(src_path)
            dst = CONF_DIR / src.name
            if dst.suffix not in (".ovpn",".conf"): dst = dst.with_suffix(".ovpn")
            shutil.copy2(src, dst)
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
        if not new_name or name == new_name: return
        for ext in (".ovpn", ".conf"):
            src = CONF_DIR / f"{name}{ext}"
            if src.exists():
                dst = CONF_DIR / f"{new_name}{ext}"
                if dst.exists():
                    self._push_log(f"[!] Duplicate failed -- {new_name}{ext} already exists"); return
                shutil.copy2(src, dst)
                self._push_log(f"[+] Duplicated: {name} -> {new_name}"); break
        self._push_profiles()

    def _do_get_config(self, name):
        for ext in (".ovpn", ".conf"):
            p = CONF_DIR / f"{name}{ext}"
            if p.exists():
                self._js(f"onConfig({json.dumps(p.read_text())})"); return
        self._js("onConfig('(empty)')")

    # -- tray --

    def _set_tray(self, status):
        state_map = {"connected":"on","disconnected":"off","connecting":"busy","reconnecting":"busy","error":"off"}
        icon = load_icon(state_map.get(status, "off"))
        self.tray.setIcon(icon)
        if getattr(self, "win", None) is not None:
            self.win.setWindowIcon(icon)
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
        self._build_qc(); self._push_profiles()
        self.win.show(); self.win.raise_(); self.win.activateWindow()

    # -- connect/disconnect --

    def _creds_path(self, name):
        safe = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in name)
        return APP_DIR / f".creds_{safe}"

    def _profile_needs_auth(self, config_path):
        try: text = Path(config_path).read_text(errors="replace")
        except Exception: return False
        in_inline = False
        for raw in text.splitlines():
            s = raw.strip()
            if not s or s.startswith("#") or s.startswith(";"): continue
            if s.startswith("<") and s.endswith(">"):
                in_inline = not s.startswith("</"); continue
            if in_inline: continue
            parts = s.split(None, 1)
            if parts[0] == "auth-user-pass" and len(parts) == 1: return True
        return False

    def do_connect(self, config, name, overrides):
        if not overrides.get("auth_user_pass") and self._profile_needs_auth(config):
            cp = self._creds_path(name)
            if cp.exists():
                overrides = dict(overrides); overrides["auth_user_pass"] = str(cp)
            else:
                self._pending_connect = (config, name, dict(overrides))
                self.show_dash()
                self._js(f"promptAuth({json.dumps(name)})")
                return
        self._start_connect(config, name, overrides)

    def _start_connect(self, config, name, overrides):
        if self.worker and self.worker.isRunning():
            self._push_log("[*] Stopping previous connection...")
            self.worker.stop(); self.worker.wait(6000); self.worker = None

        self.profile = name
        self.state["last_profile"] = name; save_state(self.state)
        self._soft_recon = False
        self._tun_ip = ""; self._tun_dev = "tun0"
        self._last_bytes_in = 0; self._last_bytes_out = 0; self._last_poll_ts = None
        self._latency_ms = -1.0
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
            self.worker.stop(); self.worker.wait(6000); self.worker = None
        self.mgmt.close()
        self._tun_ip = ""
        self.ping.set_target(None); self._latency_ms = -1.0
        if self._ks_active:
            ks_disable(); self._ks_active = False
            self._push_log("[*] Kill switch off.")
        try:
            pw = APP_DIR / ".mgmt_pw"
            if pw.exists(): pw.unlink()
        except: pass
        tc = getattr(self, "_tmp_creds", None)
        if tc:
            try:
                if tc.exists(): tc.unlink()
            except: pass
            self._tmp_creds = None
        self._set_status("disconnected")

    def _on_tun_detected(self, name): self._tun_dev = name

    def _on_vpn(self, status):
        if status == "connected":
            if not self._soft_recon: self.connected_at = datetime.now()
            self._soft_recon = False
            self.tray.showMessage("VPNTray", f"Connected: {self.profile}",
                                  QSystemTrayIcon.Information, 3000)
            if self._overrides.get("killswitch") and not self._ks_active:
                try:
                    info = self.mgmt.get_status()
                    rip = info.get("remote_ip","")
                    if rip:
                        ks_enable(rip, self._tun_dev); self._ks_active = True
                        self._push_log(f"[*] Kill switch ON ({rip} via {self._tun_dev})")
                except: pass
        elif status == "reconnecting":
            self._soft_recon = True; self.mgmt.close()
        elif status == "error":
            self.tray.showMessage("VPNTray", "Connection error", QSystemTrayIcon.Warning, 5000)
        self._set_status(status)

    def _on_latency(self, ms): self._latency_ms = ms

    def _set_status(self, status):
        self._set_tray(status)
        tip = f"VPNTray - {status.title()}"
        if status == "connected":
            tip += f"\n{self.profile}"
            if self._tun_ip: tip += f"\n{self._tun_ip}"
        self.tray.setToolTip(tip)
        self.status_act.setText(status.title() + (f" - {self.profile}" if status == "connected" else ""))
        self.dc_act.setEnabled(status in ("connected","connecting","reconnecting"))
        # send connected_at as iso string so JS can drive its own uptime ticker
        connected_iso = self.connected_at.isoformat() if (status == "connected" and self.connected_at) else None
        payload = {"state": status, "profile": self.profile, "connected_at": connected_iso}
        self._js(f"onStatus({json.dumps(payload)})")
        if status == "disconnected":
            self.connected_at = None; self._soft_recon = False; self._tun_ip = ""

    def _push_log(self, text):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {text}"
        if not self._page_ready:
            self._log_buffer.append(line)
            if len(self._log_buffer) > 500: self._log_buffer = self._log_buffer[-500:]
            return
        self._js(f"appendLog({json.dumps(line)})")

    def _poll(self):
        if not self.connected_at or not self.worker or not self.worker.isRunning():
            return
        try:
            info = self.mgmt.get_status()
            ip = info.get("local_ip", "")
            if ip and ip != self._tun_ip:
                self._tun_ip = ip
                self.tray.setToolTip(f"VPNTray - Connected\n{self.profile}\n{self._tun_ip}")

            # throughput rate -- delta over wall-clock since last poll
            now = datetime.now()
            bin_, bout = info.get("bytes_in", 0), info.get("bytes_out", 0)
            rate_in = rate_out = 0
            if self._last_poll_ts:
                dt = (now - self._last_poll_ts).total_seconds()
                if dt > 0:
                    rate_in = max(0, (bin_ - self._last_bytes_in) / dt)
                    rate_out = max(0, (bout - self._last_bytes_out) / dt)
            self._last_poll_ts = now
            self._last_bytes_in = bin_; self._last_bytes_out = bout

            info["rate_in"] = rate_in
            info["rate_out"] = rate_out
            info["latency_ms"] = self._latency_ms

            # feed the ping worker the current target
            rip = info.get("remote_ip", "")
            if rip: self.ping.set_target(rip)

            self._js(f"onStats({json.dumps(info)})")
        except Exception as e:
            msg = str(e)
            if msg != getattr(self, "_last_poll_err", None):
                self._last_poll_err = msg
                self._push_log(f"[!] poll error: {msg}")

    def _quit(self):
        try: self.ping.stop(); self.ping.wait(2000)
        except: pass
        self.do_disconnect()
        self.tray.hide()
        self.qapp.quit()

    def run(self):
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        sys.exit(self.qapp.exec_())


# the dashboard. single sodium-amber theme, terminal HUD aesthetic.
# JS->Python via console.log('BRIDGE:...'); Python->JS via runJavaScript.

HTML = r"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*,*::before,*::after { box-sizing:border-box; margin:0; padding:0; }

/* theme tokens. switching themes flips the body class and CSS vars cascade
   to everything. SVG accent colors are read at render time via getComputedStyle
   so the globe/sparklines pick up the new palette on next render. */
:root, body.theme-dark {
  --bg:#0a0e1a; --surface:#0f1422; --elevated:#141a2b; --raised:#1a2138;
  --hairline:rgba(255,255,255,.05); --bd:rgba(255,255,255,.08); --bdh:rgba(255,255,255,.14);
  --amber:#FFB347; --amber-dim:#E8923A;
  --amber-soft:rgba(255,179,71,.10); --amber-glow:rgba(255,179,71,.22);
  --amber-faint:rgba(255,179,71,.04); --amber-mid:rgba(255,179,71,.18); --amber-sel:rgba(255,179,71,.25);
  --ok:#4ade80; --warn:#fbbf24;
  --err:#f87171; --err-dim:#c44545; --err-soft:rgba(248,113,113,.10); --err-mid:rgba(248,113,113,.18);
  --cyan:#67e8f9; --cyan-faint:rgba(103,232,249,.03);
  --t:#e8eef7; --t2:#94a3b8; --t3:#64748b; --t4:#475569;
  --accent-text:#1a0f00;
  --font-body:"IBM Plex Sans","Inter",system-ui,sans-serif;
  --font-mono:"IBM Plex Mono",ui-monospace,monospace;
}
body.theme-catppuccin {
  --bg:#1e1e2e; --surface:#181825; --elevated:#313244; --raised:#45475a;
  --hairline:rgba(205,214,244,.05); --bd:rgba(205,214,244,.08); --bdh:rgba(205,214,244,.18);
  --amber:#cba6f7; --amber-dim:#a48ad8;
  --amber-soft:rgba(203,166,247,.12); --amber-glow:rgba(203,166,247,.28);
  --amber-faint:rgba(203,166,247,.05); --amber-mid:rgba(203,166,247,.20); --amber-sel:rgba(203,166,247,.28);
  --ok:#a6e3a1; --warn:#f9e2af;
  --err:#f38ba8; --err-dim:#c97090; --err-soft:rgba(243,139,168,.10); --err-mid:rgba(243,139,168,.18);
  --cyan:#89dceb; --cyan-faint:rgba(137,220,235,.04);
  --t:#cdd6f4; --t2:#bac2de; --t3:#7f849c; --t4:#6c7086;
  --accent-text:#1e1e2e;
}
body.theme-catppuccin .inp,
body.theme-catppuccin select,
body.theme-catppuccin textarea,
body.theme-catppuccin .pill,
body.theme-catppuccin .modal-btn,
body.theme-catppuccin .prof-btn,
body.theme-catppuccin .prof-go,
body.theme-catppuccin .btn-go,
body.theme-catppuccin .card,
body.theme-catppuccin .metric,
body.theme-catppuccin .hero,
body.theme-catppuccin .modal,
body.theme-catppuccin .dropzone,
body.theme-catppuccin .logs-search,
body.theme-catppuccin .logs-body,
body.theme-catppuccin .prof,
body.theme-catppuccin .themes { border-radius:12px !important; }

body.theme-cyberpunk {
  --bg:#050507; --surface:#0a0a12; --elevated:#13131e; --raised:#1c1c2c;
  --hairline:rgba(255,255,255,.04); --bd:rgba(255,255,255,.07); --bdh:rgba(255,0,170,.32);
  --amber:#ff00aa; --amber-dim:#cc0088;
  --amber-soft:rgba(255,0,170,.12); --amber-glow:rgba(255,0,170,.34);
  --amber-faint:rgba(255,0,170,.06); --amber-mid:rgba(255,0,170,.22); --amber-sel:rgba(255,0,170,.30);
  --ok:#00ff88; --warn:#ffea00;
  --err:#ff003c; --err-dim:#cc0030; --err-soft:rgba(255,0,60,.10); --err-mid:rgba(255,0,60,.20);
  --cyan:#00ffff; --cyan-faint:rgba(0,255,255,.05);
  --t:#f0f0f5; --t2:#b8b8cc; --t3:#707088; --t4:#404055;
  --accent-text:#0a0014;
  --font-body:"IBM Plex Mono",ui-monospace,monospace;
}
body.theme-cyberpunk .inp,
body.theme-cyberpunk select,
body.theme-cyberpunk textarea,
body.theme-cyberpunk .pill,
body.theme-cyberpunk .modal-btn,
body.theme-cyberpunk .prof-btn,
body.theme-cyberpunk .prof-go,
body.theme-cyberpunk .btn-go,
body.theme-cyberpunk .card,
body.theme-cyberpunk .metric,
body.theme-cyberpunk .hero,
body.theme-cyberpunk .modal,
body.theme-cyberpunk .dropzone,
body.theme-cyberpunk .logs-search,
body.theme-cyberpunk .logs-body,
body.theme-cyberpunk .prof,
body.theme-cyberpunk .themes { border-radius:2px !important; }
body.theme-cyberpunk h1 { font-family:var(--font-mono); letter-spacing:1.5px; text-transform:uppercase; text-shadow:0 0 8px var(--amber-glow); }
body.theme-cyberpunk .card-title { letter-spacing:2px; }
body.theme-cyberpunk::before {
  content:''; position:fixed; inset:0; pointer-events:none; z-index:9999;
  background: repeating-linear-gradient(0deg, rgba(255,0,170,.025) 0, rgba(255,0,170,.025) 1px, transparent 1px, transparent 3px);
  animation: scan-flicker 6s infinite; mix-blend-mode: screen;
}
body.theme-cyberpunk::after {
  content:''; position:fixed; inset:0; pointer-events:none; z-index:9998;
  background: radial-gradient(ellipse at center, transparent 60%, rgba(0,0,0,.35) 100%);
}

/* base */
html, body { height:100%; }
body {
  font-family: var(--font-body);
  font-size: 13px;
  color: var(--t);
  background:
    radial-gradient(ellipse 800px 600px at 20% 0%, var(--amber-faint), transparent 60%),
    radial-gradient(ellipse 600px 400px at 100% 100%, var(--cyan-faint), transparent 60%),
    var(--bg);
  display: flex;
  overflow: hidden;
  min-height: 720px;
}
.mono { font-family: var(--font-mono); }
.sans { font-family: var(--font-body); }
input, select, textarea, button { outline:none; font:inherit; color:inherit; }
select option { background: var(--elevated); color: var(--t); }
::-webkit-scrollbar { width:6px; height:6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(255,255,255,.08); border-radius:3px; }
::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,.15); }

/* animations */
@keyframes pulse-soft { 0%,100% { opacity:.45; transform:scale(1) } 50% { opacity:.85; transform:scale(1.08) } }
@keyframes spin-slow { from { transform:rotate(0) } to { transform:rotate(360deg) } }
@keyframes blink { 0%,100% { opacity:1 } 50% { opacity:.35 } }
@keyframes scan-flicker { 0%,96%,100% { opacity:1 } 97% { opacity:.92 } 98% { opacity:.97 } }
@keyframes fade-in { from { opacity:0 } to { opacity:1 } }

/* sidebar */
.sb {
  width: 168px; flex-shrink: 0;
  display: flex; flex-direction: column;
  background: linear-gradient(180deg, var(--surface) 0%, var(--bg) 100%);
  border-right: 1px solid var(--hairline);
}
.sb-brand { display:flex; align-items:center; gap:10px; padding:18px 16px 14px; }
.sb-mark {
  width:30px; height:30px; border-radius:8px;
  display:flex; align-items:center; justify-content:center;
  background: linear-gradient(135deg, var(--amber), var(--amber-dim));
  box-shadow: 0 4px 14px var(--amber-glow);
  color: var(--accent-text);
  position: relative; overflow: visible;
}
.sb-name { font-size:13px; font-weight:600; letter-spacing:.2px; }
.sb-ver { font-family:var(--font-mono); font-size:9.5px; color:var(--t3); letter-spacing:1px; }
.sb-sep { height:1px; background: var(--hairline); margin: 0 14px 8px; }
.sb-nav { padding: 0 8px; display:flex; flex-direction:column; gap:2px; }
.sb-btn {
  display:flex; align-items:center; gap:10px;
  padding: 8px 10px; border-radius:7px;
  background: transparent; border:none; color: var(--t2);
  cursor: pointer; text-align: left;
  font-size: 12px; font-weight: 400; letter-spacing: .1px;
  transition: background .12s, color .12s;
}
.sb-btn:hover { background: rgba(255,255,255,.03); color: var(--t); }
.sb-btn.active { background: var(--amber-soft); color: var(--amber); font-weight:500; }
.sb-btn svg { flex-shrink:0; opacity:.85; width:14px; height:14px; }
.sb-foot { margin-top:auto; padding:12px 14px; border-top:1px solid var(--hairline); }
.sb-foot-row { display:flex; align-items:center; gap:8px; margin-bottom:2px; }
.sb-dot { width:7px; height:7px; border-radius:50%; }
.sb-stat { font-family:var(--font-mono); font-size:10px; color:var(--t2); letter-spacing:.5px; }
.sb-prof { font-family:var(--font-mono); font-size:10px; color:var(--t3); padding-left:15px; }

/* main + topbar */
.main { flex:1; overflow-y:auto; padding: 16px 20px 20px; }
.topbar { display:flex; align-items:center; justify-content:space-between; margin-bottom:14px; }
.topbar-l { display:flex; align-items:baseline; gap:12px; }
.topbar h1 { font-size:18px; font-weight:500; letter-spacing:-.2px; }
.topbar-meta { font-family:var(--font-mono); font-size:10.5px; color:var(--t3); letter-spacing:1.5px; }
.topbar-r { display:flex; align-items:center; gap:8px; }
.themes {
  display:flex; align-items:center; gap:6px;
  padding: 4px 8px; border-radius: 6px;
  background: var(--surface); border:1px solid var(--bd);
}
.theme-sw {
  width:14px; height:14px; border-radius:50%; padding:0;
  border: 1.5px solid transparent;
  cursor: pointer; transition: all .15s;
}
.theme-sw.sel { border-color: var(--t); }
.pill {
  display: inline-flex; align-items: center; gap: 6px;
  background: var(--surface); border: 1px solid var(--bd); color: var(--t2);
  border-radius: 6px; padding: 5px 10px;
  font-size: 11px; cursor: pointer; font-family: var(--font-body);
}
.pill:hover { color: var(--t); border-color: var(--bdh); }
.pill svg { width:12px; height:12px; }

/* page */
.page { display:none; flex-direction:column; gap:12px; animation: fade-in .15s ease; }
.page.active { display:flex; }

/* hero */
.hero {
  display:flex; gap:16px;
  background: var(--surface); border:1px solid var(--bd);
  border-radius:12px; padding:16px 18px;
  transition: background .4s ease, border-color .4s ease;
}
.hero.connected {
  background: linear-gradient(135deg, var(--amber-faint) 0%, var(--surface) 60%);
  border-color: var(--amber-mid);
}
.hero-globe { width:220px; height:220px; flex-shrink:0; position:relative; }
.hero-side { flex:1; min-width:0; display:flex; flex-direction:column; justify-content:space-between; gap:12px; }
.hero-kicker { font-family:var(--font-mono); font-size:9.5px; color:var(--t3); letter-spacing:2px; margin-bottom:3px; }
.hero-status { display:flex; align-items:center; gap:10px; }
.hero-status .label { font-size:22px; font-weight:500; letter-spacing:-.3px; }
.hero-meta { font-family:var(--font-mono); font-size:11px; color:var(--t2); margin-top:6px; }
.hero-meta .name { color: var(--t); }
.hero-meta .sep { color: var(--t4); margin: 0 7px; }
.hero-meta .proto { color: var(--amber); }
.hero-tech { font-family:var(--font-mono); font-size:10px; color:var(--t3); margin-top:4px; }
.hero-actions { display:flex; align-items:center; gap:8px; }
.hero-actions select {
  flex:1; min-width:0;
  background: var(--elevated); color: var(--t);
  border:1px solid var(--bd); border-radius:7px;
  padding: 7px 10px; font-family: var(--font-mono); font-size: 11.5px;
  cursor: pointer;
}
.hero-actions select:disabled { opacity:.6; cursor: not-allowed; }
.btn-go {
  display:inline-flex; align-items:center; gap:6px;
  padding: 8px 18px; border-radius: 7px; border: none; cursor: pointer;
  font-family: var(--font-body); font-size: 12px; font-weight: 500; letter-spacing: .3px;
  transition: filter .15s;
}
.btn-go.connect {
  background: linear-gradient(135deg, var(--amber), var(--amber-dim));
  color: var(--accent-text); box-shadow: 0 4px 14px var(--amber-glow);
}
.btn-go.disconnect {
  background: linear-gradient(135deg, var(--err), var(--err-dim));
  color: #fff; box-shadow: 0 4px 14px rgba(248,113,113,.25);
}
.btn-go:disabled { opacity:.5; cursor: not-allowed; }

/* metrics */
.metrics { display:grid; grid-template-columns: repeat(5, 1fr); gap:8px; }
.metric { background: var(--surface); border:1px solid var(--bd); border-radius:9px; padding:10px 12px; min-width:0; }
.metric-head { display:flex; align-items:center; justify-content:space-between; margin-bottom:4px; }
.metric-label { font-family:var(--font-mono); font-size:9px; color:var(--t3); letter-spacing:1.5px; }
.metric-icon { color:var(--t3); opacity:.7; display:flex; }
.metric-icon.accent { color: var(--amber); opacity: 1; }
.metric-icon svg { width:11px; height:11px; }
.metric-val { font-family:var(--font-body); font-size:16px; font-weight:500; letter-spacing:-.2px; color:var(--t);
  white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.metric-val.mono { font-family:var(--font-mono); font-size:13px; }
.metric-val.accent { color: var(--amber); }
.metric-sub { font-family:var(--font-mono); font-size:9.5px; color:var(--t3); margin-top:1px; }

/* card */
.card { background: var(--surface); border:1px solid var(--bd); border-radius:10px; padding: 11px 14px; }
.card.danger { border-color: var(--err-mid); }
.card.accent { border-color: var(--amber-mid); }
.card-head { display:flex; align-items:center; justify-content:space-between; margin-bottom:8px; }
.card-head-l { display:flex; align-items:baseline; gap:8px; }
.card-title { font-family:var(--font-mono); font-size:9.5px; letter-spacing:1.5px; font-weight:500; color:var(--t3); }
.card-title.danger { color: var(--err); }
.card-title.accent { color: var(--amber); }
.card-sub { font-family:var(--font-mono); font-size:9.5px; color: var(--t4); }
.card-action { color: var(--t3); display:flex; }
.card-action svg { width:11px; height:11px; }

/* sparkline */
.spark-row { display:grid; grid-template-columns: 1.4fr 1fr; gap:8px; }
.spark { height:84px; margin: 4px -4px 0 -8px; }
.spark svg { width:100%; height:100%; display:block; }
.spark-legend { display:flex; align-items:center; gap:14px;
  font-family:var(--font-mono); font-size:10px; color:var(--t2); padding-left:4px; margin-top:4px; }
.spark-swatch { display:inline-block; width:8px; height:2px; vertical-align:middle; margin-right:4px; }
.spark-stats { display:flex; gap:12px;
  font-family:var(--font-mono); font-size:10px; color:var(--t3); padding-left:4px; margin-top:4px; }

/* log feed */
.log-feed { font-family:var(--font-mono); max-height:160px; overflow-y:auto;
  font-size:10.5px; line-height:17px; }
.log-line { display:flex; gap:8px; padding:1px 0; }
.log-ts { color: var(--t4); min-width:56px; flex-shrink:0; }
.log-glyph { min-width:12px; opacity:.9; }
.log-text { flex:1; word-break: break-word; }
.log-ok .log-text, .log-ok .log-glyph { color: var(--amber); }
.log-info .log-text { color: var(--t2); }
.log-info .log-glyph { color: var(--cyan); }
.log-warn .log-text, .log-warn .log-glyph { color: var(--warn); }
.log-err .log-text, .log-err .log-glyph { color: var(--err); }

/* profiles */
.dropzone {
  border: 1.5px dashed var(--bd); border-radius:10px; padding:14px;
  display:flex; align-items:center; justify-content:center; gap:8px;
  color: var(--t3); font-size: 11.5px; cursor: pointer;
  background: rgba(255,255,255,.01);
  transition: all .15s;
}
.dropzone:hover { border-color: var(--amber); color: var(--amber); }
.prof {
  display:flex; align-items:center; gap:12px;
  padding: 10px 14px; background: var(--surface);
  border: 1px solid var(--bd); border-radius:9px;
  cursor: pointer; transition: background .12s, border-color .12s;
}
.prof.sel { background: var(--amber-soft); border-color: var(--amber-sel); }
.prof-dot { width:9px; height:9px; border-radius:50%; background: var(--t4); flex-shrink:0; transition: all .15s; }
.prof.sel .prof-dot { background: var(--amber-dim); }
.prof.live .prof-dot { background: var(--amber); box-shadow: 0 0 10px var(--amber-glow);
  animation: pulse-soft 2s ease-in-out infinite; }
.prof-body { flex:1; min-width:0; }
.prof-row1 { display:flex; align-items:baseline; gap:8px; }
.prof-name { font-size:12.5px; font-weight:500; color:var(--t); }
.prof.sel .prof-name { color: var(--amber); }
.prof-meta { font-family:var(--font-mono); font-size:10px; color:var(--t3); }
.prof-row2 { font-family:var(--font-mono); font-size:9.5px; color:var(--t4); margin-top:1px; }
.prof-actions { display:flex; gap:4px; align-items:center; }
.prof-btn {
  width:26px; height:26px; border-radius:5px;
  display:flex; align-items:center; justify-content:center;
  background: rgba(255,255,255,.03); border:1px solid var(--hairline); color: var(--t2);
  cursor: pointer;
}
.prof-btn:hover { background: rgba(255,255,255,.06); color: var(--t); }
.prof-btn svg { width:12px; height:12px; }
.prof-go {
  padding: 4px 12px; border-radius:5px;
  background: linear-gradient(135deg, var(--amber), var(--amber-dim));
  color: var(--accent-text); border: none; cursor: pointer;
  font-size: 11px; font-weight: 500; margin-left: 4px;
  font-family: var(--font-body);
}

/* form */
.field { display:flex; flex-direction:column; gap:4px; }
.fl { font-family:var(--font-mono); font-size:9.5px; color:var(--t3); letter-spacing:1px; }
.inp {
  background: var(--elevated); color: var(--t);
  border: 1px solid var(--bd); border-radius:6px;
  padding: 6px 9px; font-family: var(--font-mono); font-size: 11.5px; width: 100%;
}
.inp:focus { border-color: var(--amber); }
textarea.inp { resize: vertical; min-height:60px; line-height:1.5; }
.g2 { display:grid; grid-template-columns: 1fr 1fr; gap:8px; }
.g3 { display:grid; grid-template-columns: 1fr 1fr 1fr; gap:8px; }
.g4 { display:grid; grid-template-columns: repeat(4, 1fr); gap:8px; }

/* toggle */
.tog { display:flex; align-items:flex-start; gap:10px; padding:4px 0; cursor:pointer; }
.tog-track {
  width:32px; height:18px; border-radius:9px; flex-shrink:0; margin-top:1px;
  background: rgba(255,255,255,.05); border: 1px solid var(--bd);
  position: relative; transition: all .2s; padding:0;
}
.tog-track.on { background: var(--amber-glow); border-color: var(--amber); }
.tog-knob { width:12px; height:12px; border-radius:6px; background: var(--t3);
  position:absolute; top:2px; left:2px; transition: all .2s; }
.tog-track.on .tog-knob { left:16px; background: var(--amber); box-shadow: 0 0 8px var(--amber-glow); }
.tog-label { font-size:12px; color:var(--t); }
.tog-sub { font-family:var(--font-mono); font-size:10px; color:var(--t3); margin-top:2px; }

/* logs page */
.logs-toolbar { display:flex; align-items:center; gap:8px; }
.logs-search {
  flex:1; display:flex; align-items:center; gap:8px;
  background: var(--surface); border:1px solid var(--bd);
  border-radius:7px; padding:6px 10px;
}
.logs-search input {
  background: transparent; border: none; color: var(--t);
  flex:1; font-family: var(--font-mono); font-size: 11.5px; padding: 0;
}
.logs-body {
  flex:1; font-family: var(--font-mono);
  background: var(--surface); border:1px solid var(--bd); border-radius:9px;
  padding: 12px 14px; overflow-y: auto;
  font-size: 11px; line-height: 19px; min-height: 300px;
}
.logs-foot { display:flex; align-items:center; gap:10px;
  font-family: var(--font-mono); font-size: 10px; color: var(--t3); }

/* modal */
.modal-bg { position:fixed; inset:0; background: rgba(0,0,0,.75);
  display:flex; align-items:center; justify-content:center; z-index:1000; animation: fade-in .15s; }
.modal {
  background: var(--surface); border:1px solid var(--bdh);
  border-radius:10px; padding:18px 20px;
  min-width:340px; max-width:90vw; max-height:80vh;
  display:flex; flex-direction:column; overflow:hidden;
}
.modal-title { font-family:var(--font-mono); font-size:10px; font-weight:500; letter-spacing:2px; color: var(--cyan); margin-bottom:6px; }
.modal-sub { font-size:11px; color: var(--t2); margin-bottom:14px; }
.modal-foot { display:flex; gap:6px; justify-content:flex-end; margin-top:14px; }
.modal-btn { padding: 6px 14px; border-radius:5px; border:1px solid var(--bd);
  background: rgba(255,255,255,.03); color: var(--t2); cursor: pointer;
  font-size: 11px; font-weight: 500; font-family: var(--font-body); }
.modal-btn.primary { background: var(--amber-soft); border-color: rgba(255,179,71,.35); color: var(--amber); }
.modal-btn.danger { background: var(--err-soft); border-color: rgba(248,113,113,.35); color: var(--err); }
.modal pre { font-family: var(--font-mono); font-size: 11px; color: var(--t);
  white-space: pre-wrap; word-break: break-all; flex:1; overflow:auto; padding:8px 0; line-height: 1.5; }
.modal label.cb { display:flex; align-items:center; gap:7px; font-size:11px; color:var(--t2); margin: 6px 0 12px; cursor: pointer; }

/* routes */
.route-row { display:flex; font-family:var(--font-mono); font-size:10.5px; color:var(--t2); padding:3px 0; line-height:20px; }
.route-row + .route-row { border-top: 1px solid var(--hairline); }
.route-net { flex: 1.4; color: var(--t); }
.route-dev { flex: .6;  color: var(--amber); }
.route-gw  { flex: 1.3; }
.route-m   { flex: .6;  color: var(--t3); }

/* sys */
.sys { font-family:var(--font-mono); font-size:10.5px; color:var(--t2); line-height:20px; }
.sys-row { display:flex; justify-content:space-between; padding:4px 0; }
.sys-row + .sys-row { border-top: 1px solid var(--hairline); }
.sys-key { color: var(--t3); }
</style>
</head><body class="theme-dark">

<aside class="sb">
  <div class="sb-brand">
    <div class="sb-mark" id="sb-mark"></div>
    <div>
      <div class="sb-name sans">vpntray</div>
      <div class="sb-ver">v3.2</div>
    </div>
  </div>
  <div class="sb-sep"></div>
  <nav class="sb-nav" id="nav"></nav>
  <div class="sb-foot">
    <div class="sb-foot-row">
      <span class="sb-dot" id="sb-dot"></span>
      <span class="sb-stat" id="sb-stat">TUNNEL DOWN</span>
    </div>
    <div class="sb-prof" id="sb-prof">&mdash;</div>
  </div>
</aside>

<main class="main">
  <div class="topbar">
    <div class="topbar-l">
      <h1 class="sans" id="title">Connect</h1>
      <span class="topbar-meta" id="meta">// IDLE</span>
    </div>
    <div class="topbar-r">
      <div class="themes" id="themes"></div>
      <button class="pill" id="qc-pill" onclick="quickConnect()"></button>
      <button class="pill" id="imp-pill" onclick="br('import')"></button>
    </div>
  </div>
  <div id="pages"></div>
</main>

<script>
'use strict';

// lucide-style inline SVG icons
const I = {
  power:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v10"/><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/></svg>',
  folder:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>',
  cpu:      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="2" x2="9" y2="4"/><line x1="15" y1="2" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="22"/><line x1="15" y1="20" x2="15" y2="22"/><line x1="20" y1="9" x2="22" y2="9"/><line x1="20" y1="15" x2="22" y2="15"/><line x1="2" y1="9" x2="4" y2="9"/><line x1="2" y1="15" x2="4" y2="15"/></svg>',
  shield:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  network:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><ellipse cx="12" cy="12" rx="4" ry="10"/><line x1="2" y1="12" x2="22" y2="12"/></svg>',
  file:     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="14" y2="17"/></svg>',
  cog:      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
  chevR:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>',
  arrowD:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/></svg>',
  arrowU:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="19" x2="12" y2="5"/><polyline points="5 12 12 5 19 12"/></svg>',
  clock:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
  activity: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
  radio:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14"/></svg>',
  eye:      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
  copy:     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
  trash:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>',
  filter:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>',
  x:        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
  terminal: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>',
  rotate:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>',
  zap:      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
  plus:     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>',
};

// brand mark — shield + keyhole + 3 dots radiating from top. pulse ring
// renders only when connected so the sidebar gives a quick at-a-glance signal.
function brandMark(connected) {
  const pulse = connected
    ? '<circle cx="32" cy="32" r="26" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.6"><animate attributeName="r" from="26" to="32" dur="1.8s" repeatCount="indefinite"/><animate attributeName="opacity" from="0.7" to="0" dur="1.8s" repeatCount="indefinite"/></circle>'
    : '';
  return '<svg width="18" height="18" viewBox="0 0 64 64" fill="none" stroke="currentColor">'
    + '<path d="M32 4 L8 12 V30 C8 44 18 56 32 60 C46 56 56 44 56 30 V12 L32 4 Z" fill="currentColor" fill-opacity="0.12" stroke-width="2.4" stroke-linejoin="round"/>'
    + '<circle cx="32" cy="28" r="5" stroke-width="2.4"/>'
    + '<rect x="29.5" y="28" width="5" height="14" rx="1.2" fill="currentColor" stroke="none"/>'
    + '<line x1="32" y1="4" x2="14" y2="2" stroke-width="1.4" stroke-linecap="round" opacity="0.65"/>'
    + '<line x1="32" y1="4" x2="32" y2="-2" stroke-width="1.4" stroke-linecap="round" opacity="0.65"/>'
    + '<line x1="32" y1="4" x2="50" y2="2" stroke-width="1.4" stroke-linecap="round" opacity="0.65"/>'
    + '<circle cx="14" cy="2" r="2.2" fill="currentColor" stroke="none"/>'
    + '<circle cx="32" cy="-2" r="2.2" fill="currentColor" stroke="none"/>'
    + '<circle cx="50" cy="2" r="2.2" fill="currentColor" stroke="none"/>'
    + pulse + '</svg>';
}

// geo lookup. ordered most-specific-first; substring match means a name like
// "machines_us-dedivip-1" still maps to a US position via the "us-" rule.
// profiles that don't match anything just don't get a globe node — no fake
// hash-based fallback positions.
const ME = { lat: 25.2, lng: 55.3, code: 'DXB' };
const GEO_RULES = [
  ['us-east',   {lat:39.0,  lng:-77.5,  code:'IAD', city:'Ashburn',     country:'US'}],
  ['us-west',   {lat:37.4,  lng:-122.1, code:'SFO', city:'San Jose',    country:'US'}],
  ['us-south',  {lat:32.8,  lng:-96.8,  code:'DFW', city:'Dallas',      country:'US'}],
  ['us-cent',   {lat:41.5,  lng:-93.6,  code:'CMH', city:'Columbus',    country:'US'}],
  ['eu-west',   {lat:53.3,  lng:-6.2,   code:'DUB', city:'Dublin',      country:'IE'}],
  ['eu-cent',   {lat:50.1,  lng:8.7,    code:'FRA', city:'Frankfurt',   country:'DE'}],
  ['eu-north',  {lat:59.3,  lng:18.1,   code:'ARN', city:'Stockholm',   country:'SE'}],
  ['ap-south',  {lat:19.1,  lng:72.9,   code:'BOM', city:'Mumbai',      country:'IN'}],
  ['ap-east',   {lat:35.7,  lng:139.7,  code:'NRT', city:'Tokyo',       country:'JP'}],
  ['us-',       {lat:39.0,  lng:-95.0,  code:'USA', city:'United States',country:'US'}],
  ['eu-',       {lat:50.1,  lng:8.7,    code:'FRA', city:'Frankfurt',   country:'DE'}],
  ['ap-',       {lat:1.4,   lng:103.8,  code:'SIN', city:'Singapore',   country:'SG'}],
  ['canada',    {lat:45.4,  lng:-75.7,  code:'YOW', city:'Ottawa',      country:'CA'}],
  ['london',    {lat:51.5,  lng:-0.1,   code:'LON', city:'London',      country:'GB'}],
  ['frankfurt', {lat:50.1,  lng:8.7,    code:'FRA', city:'Frankfurt',   country:'DE'}],
  ['germany',   {lat:50.1,  lng:8.7,    code:'FRA', city:'Frankfurt',   country:'DE'}],
  ['tokyo',     {lat:35.7,  lng:139.7,  code:'NRT', city:'Tokyo',       country:'JP'}],
  ['japan',     {lat:35.7,  lng:139.7,  code:'NRT', city:'Tokyo',       country:'JP'}],
  ['singapore', {lat:1.4,   lng:103.8,  code:'SIN', city:'Singapore',   country:'SG'}],
  ['sydney',    {lat:-33.9, lng:151.2,  code:'SYD', city:'Sydney',      country:'AU'}],
  ['paris',     {lat:48.9,  lng:2.3,    code:'CDG', city:'Paris',       country:'FR'}],
  ['france',    {lat:48.9,  lng:2.3,    code:'CDG', city:'Paris',       country:'FR'}],
  ['amsterdam', {lat:52.4,  lng:4.9,    code:'AMS', city:'Amsterdam',   country:'NL'}],
  ['dubai',     {lat:25.2,  lng:55.3,   code:'DXB', city:'Dubai',       country:'AE'}],
  ['mumbai',    {lat:19.1,  lng:72.9,   code:'BOM', city:'Mumbai',      country:'IN'}],
  ['india',     {lat:19.1,  lng:72.9,   code:'BOM', city:'Mumbai',      country:'IN'}],
  ['home',      {lat:23.8,  lng:90.4,   code:'DAC', city:'Dhaka',       country:'BD'}],
  ['lab',       {lat:23.8,  lng:90.4,   code:'DAC', city:'Dhaka',       country:'BD'}],
];
function lookupGeo(name) {
  if (!name) return null;
  const lc = name.toLowerCase();
  for (const [k, v] of GEO_RULES) if (lc.indexOf(k) !== -1) return v;
  return null;
}

// orthographic projection. `lat0d`/`lng0d` (in degrees) parameterise the
// view-center so we can re-center per-render — important when the active
// endpoint would otherwise sit on the back side of the globe (e.g. a US
// server viewed from a dubai-centered globe never renders, cosc < 0).
// defaults to the ME location so legacy calls still work.
function ortho(lat, lng, cx, cy, r, lat0d, lng0d) {
  const lat0 = (lat0d == null ? ME.lat : lat0d) * Math.PI / 180;
  const lng0 = (lng0d == null ? ME.lng : lng0d) * Math.PI / 180;
  const f = lat * Math.PI / 180, l = lng * Math.PI / 180;
  const cosc = Math.sin(lat0)*Math.sin(f) + Math.cos(lat0)*Math.cos(f)*Math.cos(l-lng0);
  if (cosc < 0) return null;
  const x = cx + r * Math.cos(f) * Math.sin(l - lng0);
  const y = cy - r * (Math.cos(lat0)*Math.sin(f) - Math.sin(lat0)*Math.cos(f)*Math.cos(l-lng0));
  return [x, y, cosc];
}

// formatters
function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function fmtBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b/1048576).toFixed(1) + ' MB';
  return (b/1073741824).toFixed(2) + ' GB';
}
function fmtRate(b) {
  if (b < 1024) return Math.round(b) + ' B/s';
  if (b < 1048576) return (b/1024).toFixed(0) + ' KB/s';
  return (b/1048576).toFixed(1) + ' MB/s';
}
function fmtUptime(s) {
  const h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = s%60;
  return [h,m,sec].map(n => String(n).padStart(2,'0')).join(':');
}
function setTxt(id, t) { const e = document.getElementById(id); if (e) e.textContent = t; }
function hexRgb(hex) {
  const h = (hex || '').replace('#','').trim();
  if (h.length !== 6) return '255,179,71';
  return [0,2,4].map(i => parseInt(h.slice(i,i+2),16)).join(',');
}

// nav + state
const NAV = [
  { id:'connect',  label:'Connect',  icon:I.power },
  { id:'profiles', label:'Profiles', icon:I.folder },
  { id:'tunnel',   label:'Tunnel',   icon:I.cpu },
  { id:'security', label:'Security', icon:I.shield },
  { id:'network',  label:'Network',  icon:I.network },
  { id:'logs',     label:'Logs',     icon:I.file },
  { id:'settings', label:'Settings', icon:I.cog },
];
const THEMES = ['dark', 'catppuccin', 'cyberpunk'];
const THEME_SWATCHES = { dark:'#FFB347', catppuccin:'#cba6f7', cyberpunk:'#ff00aa' };

const S = {
  page: 'connect',
  theme: 'dark',
  vpnState: 'disconnected',
  profile: '',     // python-driven, the actually-running profile name
  selected: null,  // user UI selection in dropdowns
  connectedAt: null,
  profiles: [],    // [{name, file, path}] — populated by python via onProfiles
  bytesIn: 0, bytesOut: 0, rateIn: 0, rateOut: 0,
  latency: -1, localIp: '', remoteIp: '', tunDev: '',
  // rolling buffers; populated from real polls. 48 samples * 1s = ~48s window
  throughputHist: Array.from({length:48}, () => ({down:0, up:0})),
  latencyHist:    Array.from({length:48}, () => ({v:0})),
  logs: [],
  logFilter: '',
  settings: { auto_connect:false, reconnect:true, reconnect_delay:5, dns_fix:true, killswitch:false, theme:'dark' },
  overrides: {},   // sticky cache of the override payload sent to python
  sysInfo: '(unknown)',
};

function br(cmd, data) { console.log('BRIDGE:' + cmd + ':' + JSON.stringify(data || {})); }

function applyTheme(name) {
  if (THEMES.indexOf(name) === -1) name = 'dark';
  document.body.className = 'theme-' + name;
  S.theme = name;
}

// ── sidebar / topbar / nav ─────────────────────────────────────────
function renderNav() {
  const el = document.getElementById('nav');
  el.innerHTML = NAV.map(n => '<button class="sb-btn ' + (S.page===n.id?'active':'') + '" data-id="' + n.id + '">'
    + n.icon + '<span>' + n.label + '</span>'
    + (S.page===n.id ? '<span style="margin-left:auto;opacity:.6;display:flex;width:12px;height:12px">' + I.chevR + '</span>' : '')
    + '</button>').join('');
  el.querySelectorAll('.sb-btn').forEach(b => { b.onclick = () => navigate(b.dataset.id); });
}
function renderBrandMark() {
  document.getElementById('sb-mark').innerHTML = brandMark(S.vpnState === 'connected');
}
function renderSidebarFoot() {
  const dot = document.getElementById('sb-dot');
  const stat = document.getElementById('sb-stat');
  const prof = document.getElementById('sb-prof');
  let color = 'var(--err)', text = 'TUNNEL DOWN';
  if (S.vpnState === 'connected') { color = 'var(--amber)'; text = 'TUNNEL UP'; }
  else if (S.vpnState === 'connecting') { color = 'var(--warn)'; text = 'NEGOTIATING'; }
  dot.style.background = color;
  dot.style.boxShadow = '0 0 8px ' + color;
  dot.style.animation = S.vpnState === 'connecting' ? 'blink 1.2s infinite' : 'none';
  stat.textContent = text;
  prof.textContent = S.vpnState === 'connected' ? S.profile : '—';
}
function renderTopbar() {
  const titles = { connect:'Connect', profiles:'Profiles', tunnel:'Tunnel',
                   security:'Security', network:'Network', logs:'Logs', settings:'Settings' };
  document.getElementById('title').textContent = titles[S.page] || '';
  let meta = '';
  if (S.page === 'connect')       meta = S.vpnState === 'connected' ? '// LIVE • ' + (S.latency >= 0 ? Math.round(S.latency) + 'ms' : '—') : '// IDLE';
  else if (S.page === 'profiles') meta = '// ' + S.profiles.length + ' LOADED';
  else if (S.page === 'tunnel')   meta = '// PER-CONNECTION OVERRIDES';
  else if (S.page === 'security') meta = '// HARDENING';
  else if (S.page === 'network')  meta = '// PROXY & ROUTING';
  else if (S.page === 'logs')     meta = '// LIVE TAIL';
  else if (S.page === 'settings') meta = '// PREFERENCES';
  document.getElementById('meta').textContent = meta;
  // theme swatches
  const themesEl = document.getElementById('themes');
  themesEl.innerHTML = THEMES.map(t => {
    const sel = S.theme === t;
    return '<button class="theme-sw' + (sel?' sel':'') + '" title="' + t + '" data-theme="' + t + '"'
      + ' style="background:' + THEME_SWATCHES[t] + ';box-shadow:' + (sel ? '0 0 8px ' + THEME_SWATCHES[t] + '99' : 'none') + '"></button>';
  }).join('');
  themesEl.querySelectorAll('.theme-sw').forEach(b => {
    b.onclick = () => {
      applyTheme(b.dataset.theme);
      S.overrides.theme = b.dataset.theme;
      br('setOverrides', S.overrides);
      renderTopbar(); renderPage(); renderBrandMark();
    };
  });
  // pills
  document.getElementById('qc-pill').innerHTML =
    '<span style="display:flex;width:11px;height:11px">' + I.zap + '</span>' +
    (S.vpnState === 'connected' ? 'Disconnect' : 'Quick connect');
  document.getElementById('imp-pill').innerHTML =
    '<span style="display:flex;width:11px;height:11px">' + I.plus + '</span>Import';
}

function navigate(id) { S.page = id; renderNav(); renderTopbar(); renderPage(); }
function quickConnect() {
  if (S.vpnState === 'connected') { doDisconnect(); return; }
  if (S.vpnState === 'connecting') return;
  if (S.profiles.length) {
    if (!S.selected) S.selected = S.profiles[0].name;
    doConnect();
  }
}

// ── page render ────────────────────────────────────────────────────
function renderPage() {
  const root = document.getElementById('pages');
  switch (S.page) {
    case 'connect':  root.innerHTML = pageConnect();  bindConnect(); break;
    case 'profiles': root.innerHTML = pageProfiles(); bindProfiles(); break;
    case 'tunnel':   root.innerHTML = pageTunnel();   bindOverrides(); break;
    case 'security': root.innerHTML = pageSecurity(); bindOverrides(); break;
    case 'network':  root.innerHTML = pageNetwork();  bindOverrides(); break;
    case 'logs':     root.innerHTML = pageLogs();     bindLogs(); break;
    case 'settings': root.innerHTML = pageSettings(); bindOverrides(); break;
  }
}

// ── connect page ───────────────────────────────────────────────────
function pageConnect() {
  const isCon = S.vpnState === 'connected';
  const isBusy = S.vpnState === 'connecting';
  // when running, the python-driven profile is authoritative; otherwise
  // fall back to the user's UI selection. matters for tray quick-connect
  // where S.selected may not match what's actually running.
  const liveName = (isCon || isBusy) && S.profile ? S.profile : S.selected;
  const profile = S.profiles.find(p => p.name === liveName)
                || S.profiles.find(p => p.name === S.selected)
                || S.profiles[0];
  const geo = profile ? lookupGeo(profile.name) : null;
  const status = isCon ? 'Connected' : isBusy ? 'Connecting...' : 'Disconnected';
  const statusColor = isCon ? 'var(--amber)' : isBusy ? 'var(--warn)' : 'var(--err)';
  const kicker = isCon ? 'SECURE TUNNEL ACTIVE' : isBusy ? 'ESTABLISHING TUNNEL' : 'NO ACTIVE TUNNEL';

  const peakDown = Math.max(0, ...S.throughputHist.map(d => d.down));
  const peakUp   = Math.max(0, ...S.throughputHist.map(d => d.up));
  const latVals = S.latencyHist.filter(l => l.v > 0).map(l => l.v);
  const latMin = latVals.length ? Math.min(...latVals).toFixed(0) : '—';
  const latAvg = latVals.length ? (latVals.reduce((a,b)=>a+b,0)/latVals.length).toFixed(0) : '—';
  const latMax = latVals.length ? Math.max(...latVals).toFixed(0) : '—';

  const profOpts = S.profiles.length
    ? S.profiles.map(p => {
        const g = lookupGeo(p.name);
        const tail = g ? ' — ' + g.city + ', ' + g.country : '';
        return '<option value="' + esc(p.name) + '"' + (p.name === S.selected ? ' selected' : '') + '>'
          + esc(p.name) + esc(tail) + '</option>';
      }).join('')
    : '<option value="">(no profiles imported)</option>';

  let metaHtml;
  if (isCon && profile) {
    const cityCountry = geo ? geo.city + ', ' + geo.country : '';
    metaHtml = '<span class="name">' + esc(profile.name) + '</span>'
      + (cityCountry ? '<span class="sep">·</span><span>' + esc(cityCountry) + '</span>' : '')
      + (S.remoteIp ? '<span class="sep">·</span><span class="proto">' + esc(S.remoteIp) + '</span>' : '');
  } else {
    metaHtml = '<span>Select a profile and connect</span>';
  }

  // tech line uses real values only — no fake AES/TLS unless we know it
  const techParts = [];
  if (S.tunDev) techParts.push(esc(S.tunDev));
  if (S.localIp) techParts.push(esc(S.localIp));
  if (S.remoteIp) techParts.push('→ ' + esc(S.remoteIp));
  const techHtml = (isCon && techParts.length)
    ? '<div class="hero-tech">' + techParts.join(' · ') + '</div>'
    : '';

  const goDisabled = (!S.profiles.length && !isCon && !isBusy) ? 'disabled' : '';

  return '<div class="page active">'
    + '<div class="hero ' + (isCon ? 'connected' : '') + '">'
    +   '<div class="hero-globe" id="globe-host">' + renderGlobe(profile, geo) + '</div>'
    +   '<div class="hero-side">'
    +     '<div>'
    +       '<div class="hero-kicker">' + kicker + '</div>'
    +       '<div class="hero-status">'
    +         '<span class="label" style="color:' + statusColor + '">' + status + '</span>'
    +         (isBusy ? '<span style="display:flex;width:16px;height:16px;color:var(--warn);animation:spin-slow 1.4s linear infinite">' + I.rotate + '</span>' : '')
    +       '</div>'
    +       '<div class="hero-meta">' + metaHtml + '</div>'
    +       techHtml
    +     '</div>'
    +     '<div class="hero-actions">'
    +       '<select id="hero-sel"' + (isCon || isBusy ? ' disabled' : '') + '>' + profOpts + '</select>'
    +       '<button class="btn-go ' + (isCon ? 'disconnect' : 'connect') + '" id="hero-go"' + (goDisabled ? ' disabled' : '') + '>'
    +         '<span style="display:flex;width:13px;height:13px">' + I.power + '</span>'
    +         (isCon ? 'Disconnect' : isBusy ? 'Cancel' : 'Connect')
    +       '</button>'
    +     '</div>'
    +   '</div>'
    + '</div>'

    + '<div class="metrics">'
    +   '<div class="metric">'
    +     '<div class="metric-head"><span class="metric-label">UPTIME</span><span class="metric-icon ' + (isCon?'accent':'') + '">' + I.clock + '</span></div>'
    +     '<div class="metric-val ' + (isCon?'accent':'') + '" id="m-up">' + (isCon ? '00:00:00' : '—') + '</div>'
    +   '</div>'
    +   '<div class="metric">'
    +     '<div class="metric-head"><span class="metric-label">DOWN</span><span class="metric-icon">' + I.arrowD + '</span></div>'
    +     '<div class="metric-val" id="m-dl">' + fmtBytes(S.bytesIn) + '</div>'
    +     '<div class="metric-sub" id="m-dl-sub">' + (isCon ? fmtRate(S.rateIn) : '') + '</div>'
    +   '</div>'
    +   '<div class="metric">'
    +     '<div class="metric-head"><span class="metric-label">UP</span><span class="metric-icon">' + I.arrowU + '</span></div>'
    +     '<div class="metric-val" id="m-ul">' + fmtBytes(S.bytesOut) + '</div>'
    +     '<div class="metric-sub" id="m-ul-sub">' + (isCon ? fmtRate(S.rateOut) : '') + '</div>'
    +   '</div>'
    +   '<div class="metric">'
    +     '<div class="metric-head"><span class="metric-label">LATENCY</span><span class="metric-icon">' + I.activity + '</span></div>'
    +     '<div class="metric-val" id="m-lat">' + (isCon && S.latency >= 0 ? Math.round(S.latency) + ' ms' : '—') + '</div>'
    +     '<div class="metric-sub" id="m-lat-sub"></div>'
    +   '</div>'
    +   '<div class="metric">'
    +     '<div class="metric-head"><span class="metric-label">ENDPOINT</span><span class="metric-icon">' + I.radio + '</span></div>'
    +     '<div class="metric-val mono" id="m-ep">' + (isCon && S.remoteIp ? esc(S.remoteIp) : '—') + '</div>'
    +     '<div class="metric-sub" id="m-ep-sub">' + (isCon && S.tunDev ? esc(S.tunDev) : '') + '</div>'
    +   '</div>'
    + '</div>'

    + '<div class="spark-row">'
    +   '<div class="card">'
    +     '<div class="card-head"><div class="card-head-l"><span class="card-title">THROUGHPUT</span><span class="card-sub">· last 48s</span></div></div>'
    +     '<div class="spark" id="spark-tp">' + sparkThroughput() + '</div>'
    +     '<div class="spark-legend">'
    +       '<span><span class="spark-swatch" style="background:var(--amber)"></span>down <span style="color:var(--t3)">peak ' + fmtRate(peakDown) + '</span></span>'
    +       '<span><span class="spark-swatch" style="background:var(--cyan)"></span>up <span style="color:var(--t3)">peak ' + fmtRate(peakUp) + '</span></span>'
    +     '</div>'
    +   '</div>'
    +   '<div class="card">'
    +     '<div class="card-head"><div class="card-head-l"><span class="card-title">LATENCY</span><span class="card-sub" id="spark-lat-sub">· ' + (isCon && S.latency >= 0 ? Math.round(S.latency) + 'ms current' : '—') + '</span></div></div>'
    +     '<div class="spark" id="spark-lat">' + sparkLatency() + '</div>'
    +     '<div class="spark-stats"><span>min ' + latMin + '</span><span>avg ' + latAvg + '</span><span>max ' + latMax + '</span></div>'
    +   '</div>'
    + '</div>'

    + '<div class="card">'
    +   '<div class="card-head"><div class="card-head-l"><span class="card-title">LIVE LOG</span><span class="card-sub">· ' + (isCon ? 'streaming' : 'paused') + '</span></div><span class="card-action">' + I.terminal + '</span></div>'
    +   '<div class="log-feed" id="log-prev"></div>'
    + '</div>'

    + '</div>';
}
function bindConnect() {
  const sel = document.getElementById('hero-sel');
  if (sel) sel.onchange = e => { S.selected = e.target.value; renderPage(); };
  const go = document.getElementById('hero-go');
  if (go) go.onclick = () => S.vpnState === 'connected' ? doDisconnect() : doConnect();
  flushLogToDom();
}

// ── globe ──────────────────────────────────────────────────────────
// faithful translation of the JSX target:
//   • lit sphere with a soft radial gradient fill
//   • subtle wireframe mesh (parallels every 20°, meridians every 30°)
//   • network-node markers for each profile that has a known geo
//   • thin mesh links between proximate visible nodes
//   • active arc with glow underlay + 3 staggered particles via animateMotion
//   • cyan you-are-here pulse
//   • single "DXB → CODE" route label, no HUD chrome
//
// IMPORTANT: this is rendered ONCE per state change (renderPage runs from
// onStatus). it's NOT rebuilt every stats tick — that's what was breaking
// the SMIL animations before. innerHTML replacement restarts every animation;
// at a 1s rebuild cadence, nothing ever finishes a cycle.
function renderGlobe(profile, geo) {
  const cx = 110, cy = 110, r = 86;
  const isCon = S.vpnState === 'connected';
  const isBusy = S.vpnState === 'connecting';

  // dynamic view center — midpoint of ME and the active endpoint, so both
  // sides of the connection always land on the visible hemisphere. fixes
  // the case where e.g. a US endpoint (lng -95) is on the back side of a
  // dubai-centered globe (cosc < 0) and the arc never renders.
  let centerLat = ME.lat, centerLng = ME.lng;
  if (geo) {
    centerLat = (ME.lat + geo.lat) / 2;
    let dLng = geo.lng - ME.lng;
    if (dLng > 180) dLng -= 360;
    else if (dLng < -180) dLng += 360;
    centerLng = ME.lng + dLng / 2;
  }
  const me = ortho(ME.lat, ME.lng, cx, cy, r, centerLat, centerLng);
  const ep = geo ? ortho(geo.lat, geo.lng, cx, cy, r, centerLat, centerLng) : null;

  // nodes — every profile with a known geo. no fake fallbacks.
  const nodes = [];
  for (const p of S.profiles) {
    const g = lookupGeo(p.name);
    if (!g) continue;
    const proj = ortho(g.lat, g.lng, cx, cy, r, centerLat, centerLng);
    if (!proj) continue;
    nodes.push({ name: p.name, x: proj[0], y: proj[1], depth: proj[2] });
  }
  // links — every pair within ~0.78r so we get a few good triangles, not noise
  const links = [];
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j];
      const dx = a.x - b.x, dy = a.y - b.y;
      const d = Math.sqrt(dx*dx + dy*dy);
      if (d < r * 0.78) links.push({ a, b });
    }
  }

  // wireframe mesh — sample-and-clip
  const meshPath = (pts) => {
    let d = '', drawing = false;
    for (const [la, lo] of pts) {
      const p = ortho(la, lo, cx, cy, r, centerLat, centerLng);
      if (!p) { drawing = false; continue; }
      d += (drawing ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1) + ' ';
      drawing = true;
    }
    return d;
  };
  const lats = [];
  for (let lat = -60; lat <= 60; lat += 20) {
    const pts = []; for (let lng = -180; lng <= 180; lng += 4) pts.push([lat, lng]);
    lats.push({ d: meshPath(pts), eq: lat === 0 });
  }
  const lngs = [];
  for (let lng = -180; lng < 180; lng += 30) {
    const pts = []; for (let lat = -88; lat <= 88; lat += 4) pts.push([lat, lng]);
    lngs.push({ d: meshPath(pts), pm: lng === 0 });
  }

  // active arc — quadratic bezier from me to endpoint, control pulled outward
  let arcD = '';
  if (me && ep) {
    const mx = (me[0] + ep[0]) / 2, my = (me[1] + ep[1]) / 2;
    const dx = mx - cx, dy = my - cy;
    const d = Math.sqrt(dx*dx + dy*dy) || 1;
    const lift = 38;
    arcD = 'M ' + me[0].toFixed(1) + ' ' + me[1].toFixed(1)
         + ' Q ' + (mx + (dx/d)*lift).toFixed(1) + ' ' + (my + (dy/d)*lift).toFixed(1)
         + ' '   + ep[0].toFixed(1) + ' ' + ep[1].toFixed(1);
  }

  const meshOpacity = isCon ? 0.18 : isBusy ? 0.14 : 0.09;
  const arcAlive = isCon || isBusy;
  // resolve theme accent at render time so theme switches apply on next render
  const cs = getComputedStyle(document.body);
  const amber = (cs.getPropertyValue('--amber') || '#FFB347').trim();
  const warn  = (cs.getPropertyValue('--warn')  || '#fbbf24').trim();
  const cyan  = (cs.getPropertyValue('--cyan')  || '#67e8f9').trim();
  const t3    = (cs.getPropertyValue('--t3')    || '#64748b').trim();
  const t4    = (cs.getPropertyValue('--t4')    || '#475569').trim();
  const elev  = (cs.getPropertyValue('--elevated') || '#141a2b').trim();
  const surf  = (cs.getPropertyValue('--surface')  || '#0f1422').trim();
  const bg    = (cs.getPropertyValue('--bg')       || '#0a0e1a').trim();
  const arcCol = isCon ? amber : isBusy ? warn : t4;
  const rgb = hexRgb(amber);
  const meshCol    = 'rgba(' + rgb + ',' + meshOpacity.toFixed(3) + ')';
  const meshAccent = 'rgba(' + rgb + ',' + (meshOpacity * 1.8).toFixed(3) + ')';
  const activeName = profile ? profile.name : null;

  // unique IDs so multiple Globe instances don't collide on filter/gradient defs
  const sphId = 'sph-' + Math.random().toString(36).slice(2,8);
  const glwId = 'glw-' + Math.random().toString(36).slice(2,8);
  const arcId = 'arc-' + Math.random().toString(36).slice(2,8);

  let svg = '<svg width="220" height="220" viewBox="0 0 220 220" style="overflow:visible">';
  svg += '<defs>'
       + '<radialGradient id="' + sphId + '" cx="40%" cy="35%">'
       +   '<stop offset="0%" stop-color="' + elev + '" stop-opacity="0.55"/>'
       +   '<stop offset="55%" stop-color="' + surf + '" stop-opacity="0.85"/>'
       +   '<stop offset="100%" stop-color="' + bg + '" stop-opacity="0.95"/>'
       + '</radialGradient>'
       + '<filter id="' + glwId + '" x="-50%" y="-50%" width="200%" height="200%">'
       +   '<feGaussianBlur stdDeviation="1.6"/>'
       + '</filter>'
       + '</defs>';
  svg += '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="url(#' + sphId + ')"/>';
  svg += '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="' + meshAccent + '" stroke-width="0.5"/>';
  for (const l of lngs) {
    svg += '<path d="' + l.d + '" fill="none" stroke="' + (l.pm ? meshAccent : meshCol) + '" stroke-width="' + (l.pm ? 0.55 : 0.4) + '"/>';
  }
  for (const l of lats) {
    svg += '<path d="' + l.d + '" fill="none" stroke="' + (l.eq ? meshAccent : meshCol) + '" stroke-width="' + (l.eq ? 0.55 : 0.4) + '"/>';
  }
  for (const lk of links) {
    const minDepth = Math.min(lk.a.depth, lk.b.depth);
    svg += '<line x1="' + lk.a.x.toFixed(1) + '" y1="' + lk.a.y.toFixed(1)
         + '" x2="' + lk.b.x.toFixed(1) + '" y2="' + lk.b.y.toFixed(1)
         + '" stroke="' + amber + '" stroke-width="0.45" opacity="' + (0.12 + minDepth * 0.18).toFixed(2) + '"/>';
  }
  for (let i = 0; i < nodes.length; i++) {
    const n = nodes[i];
    const isActive = n.name === activeName;
    const base = 0.55 + n.depth * 0.45;
    const beg = (i * 0.35).toFixed(2);
    svg += '<circle cx="' + n.x.toFixed(1) + '" cy="' + n.y.toFixed(1) + '" r="4" fill="' + amber + '" opacity="' + (base * 0.22).toFixed(2) + '" filter="url(#' + glwId + ')"/>';
    svg += '<circle cx="' + n.x.toFixed(1) + '" cy="' + n.y.toFixed(1) + '" r="' + (isActive ? 2.2 : 1.6) + '" fill="' + amber + '" opacity="' + base.toFixed(2) + '">'
         + '<animate attributeName="opacity" values="' + (base*0.55).toFixed(2) + ';' + base.toFixed(2) + ';' + (base*0.55).toFixed(2) + '" dur="2.6s" begin="' + beg + 's" repeatCount="indefinite"/>'
         + '</circle>';
    if (isActive && S.vpnState !== 'disconnected') {
      svg += '<circle cx="' + n.x.toFixed(1) + '" cy="' + n.y.toFixed(1) + '" r="5" fill="none" stroke="' + amber + '" stroke-width="1.1" opacity="0.7">'
           + '<animate attributeName="r" from="4" to="15" dur="1.8s" repeatCount="indefinite"/>'
           + '<animate attributeName="opacity" from="0.85" to="0" dur="1.8s" repeatCount="indefinite"/>'
           + '</circle>';
    }
  }
  if (arcD) {
    svg += '<path id="' + arcId + '" d="' + arcD + '" stroke="' + arcCol + '" stroke-width="2.2" fill="none" opacity="' + (arcAlive ? 0.35 : 0.15) + '" filter="url(#' + glwId + ')" stroke-linecap="round"/>';
    svg += '<path d="' + arcD + '" stroke="' + arcCol + '" stroke-width="1.2" fill="none" opacity="' + (arcAlive ? 0.95 : 0.4) + '" stroke-linecap="round"/>';
    if (arcAlive) {
      const dur = isBusy ? 1.2 : 2.4;
      [0, 0.33, 0.66].forEach(d => {
        svg += '<circle r="2.1" fill="' + amber + '" opacity="0.95" filter="url(#' + glwId + ')">'
             + '<animateMotion dur="' + dur + 's" repeatCount="indefinite" begin="' + (d * dur).toFixed(2) + 's">'
             +   '<mpath href="#' + arcId + '"/>'
             + '</animateMotion>'
             + '</circle>';
      });
    }
  }
  if (me) {
    svg += '<g>'
         +   '<circle cx="' + me[0].toFixed(1) + '" cy="' + me[1].toFixed(1) + '" r="3.2" fill="' + cyan + '" opacity="0.25" filter="url(#' + glwId + ')"/>'
         +   '<circle cx="' + me[0].toFixed(1) + '" cy="' + me[1].toFixed(1) + '" r="2" fill="' + cyan + '"/>'
         +   '<circle cx="' + me[0].toFixed(1) + '" cy="' + me[1].toFixed(1) + '" r="4" fill="none" stroke="' + cyan + '" stroke-width="0.7" opacity="0.5">'
         +     '<animate attributeName="r" from="3" to="13" dur="2.4s" repeatCount="indefinite"/>'
         +     '<animate attributeName="opacity" from="0.55" to="0" dur="2.4s" repeatCount="indefinite"/>'
         +   '</circle>'
         + '</g>';
  }
  const code = geo ? geo.code : (profile ? profile.name.split(/[-_]/)[0].slice(0,3).toUpperCase() : '—');
  svg += '<text x="110" y="212" fill="' + t3 + '" font-size="8.5" letter-spacing="1.5"'
       + ' font-family=' + "'IBM Plex Mono',monospace" + ' text-anchor="middle"'
       + ' opacity="' + (S.vpnState === 'disconnected' ? 0.5 : 0.85) + '">DXB → ' + code + '</text>';
  svg += '</svg>';
  return svg;
}

// ── sparklines ─────────────────────────────────────────────────────
// vanilla SVG, smoothed via catmull-rom -> cubic bezier so it visually
// matches recharts AreaChart without pulling in the library.
function smoothPath(data, key, w, h, max) {
  const m = max || Math.max(1, ...data.map(d => d[key] || 0));
  const sx = w / Math.max(1, data.length - 1);
  const pts = data.map((d, i) => [i * sx, h - ((d[key]||0) / m) * h * 0.85 - h * 0.05]);
  if (pts.length === 0) return { line:'', area:'' };
  if (pts.length === 1) return { line:'M ' + pts[0][0] + ' ' + pts[0][1], area:'M ' + pts[0][0] + ' ' + pts[0][1] + ' L ' + pts[0][0] + ' ' + h + ' Z' };
  let line = 'M ' + pts[0][0].toFixed(1) + ' ' + pts[0][1].toFixed(1);
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i === 0 ? 0 : i - 1];
    const p1 = pts[i];
    const p2 = pts[i + 1];
    const p3 = pts[i + 2 < pts.length ? i + 2 : i + 1];
    const c1x = p1[0] + (p2[0] - p0[0]) / 6;
    const c1y = p1[1] + (p2[1] - p0[1]) / 6;
    const c2x = p2[0] - (p3[0] - p1[0]) / 6;
    const c2y = p2[1] - (p3[1] - p1[1]) / 6;
    line += ' C ' + c1x.toFixed(1) + ' ' + c1y.toFixed(1)
         + ' '   + c2x.toFixed(1) + ' ' + c2y.toFixed(1)
         + ' '   + p2[0].toFixed(1) + ' ' + p2[1].toFixed(1);
  }
  const area = line + ' L ' + w + ' ' + h + ' L 0 ' + h + ' Z';
  return { line, area };
}
function sparkThroughput() {
  const w = 380, h = 84;
  const max = Math.max(1, ...S.throughputHist.map(d => Math.max(d.down, d.up)));
  const dn = smoothPath(S.throughputHist, 'down', w, h, max);
  const up = smoothPath(S.throughputHist, 'up',   w, h, max);
  const cs = getComputedStyle(document.body);
  const amber = (cs.getPropertyValue('--amber') || '#FFB347').trim();
  const cyan  = (cs.getPropertyValue('--cyan')  || '#67e8f9').trim();
  return '<svg viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">'
       + '<defs>'
       +   '<linearGradient id="gd" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="' + amber + '" stop-opacity="0.4"/><stop offset="100%" stop-color="' + amber + '" stop-opacity="0"/></linearGradient>'
       +   '<linearGradient id="gu" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="' + cyan + '" stop-opacity="0.3"/><stop offset="100%" stop-color="' + cyan + '" stop-opacity="0"/></linearGradient>'
       + '</defs>'
       + '<path d="' + dn.area + '" fill="url(#gd)"/>'
       + '<path d="' + dn.line + '" stroke="' + amber + '" stroke-width="1.4" fill="none"/>'
       + '<path d="' + up.area + '" fill="url(#gu)"/>'
       + '<path d="' + up.line + '" stroke="' + cyan + '" stroke-width="1.4" fill="none"/>'
       + '</svg>';
}
function sparkLatency() {
  const w = 280, h = 84;
  const data = S.latencyHist.map(l => ({ v: l.v > 0 ? l.v : 0 }));
  const max = Math.max(1, ...data.map(d => d.v));
  const p = smoothPath(data, 'v', w, h, max);
  const cs = getComputedStyle(document.body);
  const amber = (cs.getPropertyValue('--amber') || '#FFB347').trim();
  return '<svg viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none"><path d="' + p.line + '" stroke="' + amber + '" stroke-width="1.4" fill="none"/></svg>';
}
function refreshSparks() {
  const tp = document.getElementById('spark-tp');
  if (tp) tp.innerHTML = sparkThroughput();
  const lat = document.getElementById('spark-lat');
  if (lat) lat.innerHTML = sparkLatency();
}

// ── profiles page ──────────────────────────────────────────────────
function pageProfiles() {
  const items = S.profiles.map(p => {
    const sel = p.name === S.selected;
    const live = p.name === S.profile && S.vpnState === 'connected';
    const geo = lookupGeo(p.name);
    const meta = geo ? esc(geo.city) + ', ' + esc(geo.country) : esc(p.file);
    return '<div class="prof' + (sel ? ' sel' : '') + (live ? ' live' : '') + '" data-name="' + esc(p.name) + '">'
      + '<div class="prof-dot"></div>'
      + '<div class="prof-body">'
      +   '<div class="prof-row1"><span class="prof-name">' + esc(p.name) + '</span><span class="prof-meta">' + meta + '</span></div>'
      +   '<div class="prof-row2">' + esc(p.file) + (geo ? ' · ' + geo.code : '') + '</div>'
      + '</div>'
      + '<div class="prof-actions">'
      +   '<button class="prof-btn" title="View" data-act="view" data-name="' + esc(p.name) + '">' + I.eye + '</button>'
      +   '<button class="prof-btn" title="Duplicate" data-act="dup" data-name="' + esc(p.name) + '">' + I.copy + '</button>'
      +   '<button class="prof-btn" title="Remove" data-act="rm" data-name="' + esc(p.name) + '">' + I.trash + '</button>'
      +   (sel && S.vpnState === 'disconnected' ? '<button class="prof-go" data-act="go">Go</button>' : '')
      + '</div>'
      + '</div>';
  }).join('') || '<div class="mono" style="color:var(--t3);text-align:center;padding:40px;font-size:11.5px">No profiles imported. Drop .ovpn / .conf files above.</div>';

  return '<div class="page active">'
    + '<div class="dropzone" onclick="br(' + "'import'" + ')"><span style="display:flex;width:14px;height:14px">' + I.plus + '</span><span>Drop .ovpn / .conf files here — or click to browse</span></div>'
    + '<div style="display:flex;flex-direction:column;gap:6px">' + items + '</div>'
    + '</div>';
}
function bindProfiles() {
  document.querySelectorAll('.prof').forEach(el => {
    el.onclick = () => { S.selected = el.dataset.name; renderPage(); };
  });
  document.querySelectorAll('.prof-btn,.prof-go').forEach(b => {
    b.addEventListener('click', e => {
      e.stopPropagation();
      const act = b.dataset.act;
      const name = b.dataset.name || S.selected;
      if (act === 'view') br('getConfig', { name });
      else if (act === 'dup') modalPrompt('New profile name:', name + '_copy', nn => { if (nn) br('duplicate', { name, new_name: nn }); });
      else if (act === 'rm')  modalConfirm('Remove profile "' + name + '"?', ok => { if (ok) br('remove', { name }); });
      else if (act === 'go')  { doConnect(); navigate('connect'); }
    });
  });
}

// ── tunnel page ────────────────────────────────────────────────────
function pageTunnel() {
  const tunings = [['MTU','ov-mtu','1500'],['Frag','ov-frag','1300'],['MSSFix','ov-mss','1450'],['Port','ov-port','1194'],
                   ['KA Int','ov-ki','10'],['KA Timeout','ov-kt','60'],['Ping','ov-ping','15'],['Ping-rst','ov-pr','120'],
                   ['Reneg-sec','ov-reneg','3600'],['Sndbuf','ov-sndbuf','393216'],['Rcvbuf','ov-rcvbuf','393216'],['TxQ','ov-txq','1000']];
  return '<div class="page active">'
    + '<div class="mono" style="font-size:10.5px;color:var(--t3)">Per-connection openvpn flag overrides. Defaults to whatever the .ovpn specifies.</div>'
    + '<div class="card">'
    +   '<div class="card-head"><div class="card-head-l"><span class="card-title">PROTOCOL & CRYPTO</span></div></div>'
    +   '<div class="g3">'
    +     field('PROTOCOL', selOpts('ov-proto', ['(default)','udp','tcp','udp4','tcp4','udp6','tcp6']))
    +     field('CIPHER',   selOpts('ov-cipher',['(default)','AES-256-GCM','AES-128-GCM','CHACHA20-POLY1305','AES-256-CBC','AES-128-CBC','BF-CBC','NONE']))
    +     field('AUTH',     selOpts('ov-auth',  ['(default)','SHA256','SHA384','SHA512','SHA1','MD5','NONE']))
    +     field('COMPRESS', selOpts('ov-comp',  ['(none)','lzo','lz4','lz4-v2','stub','migrate']))
    +     field('DEVICE',   selOpts('ov-dev',   ['(default)','tun','tap']))
    +     field('TLS MIN',  selOpts('ov-tls',   ['(default)','1.0','1.1','1.2','1.3']))
    +   '</div>'
    + '</div>'
    + '<div class="card">'
    +   '<div class="card-head"><div class="card-head-l"><span class="card-title">TUNING</span></div></div>'
    +   '<div class="g4">' + tunings.map(t => field(t[0].toUpperCase(), '<input type="number" class="inp" id="' + t[1] + '" placeholder="' + t[2] + '">')).join('') + '</div>'
    + '</div>'
    + '<div class="card">'
    +   '<div class="card-head"><div class="card-head-l"><span class="card-title">BEHAVIOR</span></div></div>'
    +   '<div class="g2" style="margin-bottom:10px">'
    +     field('VERBOSITY', selOpts('ov-verb', ['3','0','1','2','4','5','6','7']))
    +     field('REDIRECT GW', selOpts('ov-rg', ['(default)','def1','def1 bypass-dhcp','local','autolocal','def1 block-local']))
    +   '</div>'
    +   '<div style="display:flex;gap:20px;flex-wrap:wrap">'
    +     tog('ov-float', false, '--float', 'allow remote IP changes')
    +     tog('ov-nobind', true,  '--nobind', "don't bind local addr")
    +     tog('ov-ptun',   true,  '--persist-tun', 'keep tun across restart')
    +   '</div>'
    + '</div>'
    + '</div>';
}

// ── security page ──────────────────────────────────────────────────
function pageSecurity() {
  const ks = !!S.settings.killswitch;
  const dns = S.settings.dns_fix !== false;
  const ksStrip = ks ? '<div class="mono" style="background:var(--err-soft);border:1px solid rgba(248,113,113,.2);border-radius:6px;padding:8px 10px;font-size:10px;color:var(--err);margin-top:10px;margin-left:42px">ACTIVE — chain VPNTRAY_KS · LAN exempt (10/8, 172.16/12, 192.168/16)</div>' : '';
  return '<div class="page active">'
    + '<div class="card' + (ks ? ' danger' : '') + '">'
    +   '<div class="card-head"><div class="card-head-l"><span class="card-title' + (ks ? ' danger' : '') + '">KILL SWITCH</span></div></div>'
    +   tog('ov-ks', ks, 'Block all traffic if VPN drops', 'iptables rules. LAN stays accessible. Whitelists tun device + server IP.')
    +   ksStrip
    + '</div>'
    + '<div class="card' + (dns ? ' accent' : '') + '">'
    +   '<div class="card-head"><div class="card-head-l"><span class="card-title' + (dns ? ' accent' : '') + '">DNS</span></div></div>'
    +   tog('ov-dns', dns, 'DNS leak prevention', 'Forces DNS through tunnel via update-resolv-conf script')
    + '</div>'
    + '<div class="card">'
    +   '<div class="card-head"><div class="card-head-l"><span class="card-title">AUTH</span></div></div>'
    +   field('AUTH-USER-PASS FILE',
            '<div style="display:flex;gap:6px"><input type="text" class="inp" id="ov-authfile" placeholder="/path/to/auth.txt" style="flex:1"><button class="prof-btn" style="width:auto;padding:0 14px" onclick="br(' + "'browseAuth'" + ')">...</button></div>')
    +   '<div class="mono" style="font-size:9.5px;color:var(--t4);margin-top:6px">Two-line file: username on line 1, password on line 2. Mode 0600. Or leave blank — vpntray will prompt on connect when the .ovpn requires it.</div>'
    + '</div>'
    + '<div class="card">'
    +   '<div class="card-head"><div class="card-head-l"><span class="card-title">PULL FILTERS</span></div></div>'
    +   field('DIRECTIVES (one per line)', '<textarea class="inp" id="ov-pf" rows="3" placeholder=' + "'ignore &quot;dhcp-option&quot;\\naccept &quot;redirect-gateway&quot;'" + '></textarea>')
    + '</div>'
    + '</div>';
}

// ── network page ───────────────────────────────────────────────────
function pageNetwork() {
  const showRoutes = S.vpnState === 'connected';
  const routesCard = showRoutes
    ? '<div class="card">'
    +   '<div class="card-head"><div class="card-head-l"><span class="card-title">ACTIVE ENDPOINTS</span><span class="card-sub">· from server</span></div></div>'
    +   '<div>'
    +     '<div class="route-row"><span class="route-net">tunnel</span><span class="route-dev">' + esc(S.tunDev || 'tun0') + '</span><span class="route-gw">' + esc(S.localIp || '—') + '</span><span class="route-m">local</span></div>'
    +     '<div class="route-row"><span class="route-net">remote</span><span class="route-dev">—</span><span class="route-gw">' + esc(S.remoteIp || '—') + '</span><span class="route-m">server</span></div>'
    +   '</div>'
    + '</div>'
    : '';
  return '<div class="page active">'
    + '<div class="card">'
    +   '<div class="card-head"><div class="card-head-l"><span class="card-title">PROXY</span></div></div>'
    +   '<div style="display:grid;grid-template-columns:120px 1fr 100px;gap:8px">'
    +     field('TYPE', selOpts('ov-px', ['(none)','http','socks5']))
    +     field('HOST', '<input type="text" class="inp" id="ov-pxh" placeholder="proxy.corp.local">')
    +     field('PORT', '<input type="number" class="inp" id="ov-pxp" placeholder="8080">')
    +   '</div>'
    +   field('AUTH FILE', '<input type="text" class="inp" id="ov-pxa" placeholder="(optional) /path/to/proxy-auth.txt" style="margin-top:8px">')
    + '</div>'
    + '<div class="card">'
    +   '<div class="card-head"><div class="card-head-l"><span class="card-title">ROUTING</span></div></div>'
    +   tog('ov-rnp', false, 'Ignore server-pushed routes', '--route-nopull. only adds routes you specify below.')
    +   field('CUSTOM ROUTES', '<textarea class="inp" id="ov-routes" rows="3" placeholder="10.42.0.0 255.255.0.0&#10;172.20.0.0 255.255.0.0 vpn_gateway"></textarea>')
    +   '<div class="mono" style="font-size:9.5px;color:var(--t4);margin-top:6px">Format: <span style="color:var(--t2)">NETWORK NETMASK [GATEWAY] [METRIC]</span></div>'
    + '</div>'
    + routesCard
    + '</div>';
}

// ── logs page ──────────────────────────────────────────────────────
function pageLogs() {
  const clearX = S.logFilter ? '<span style="cursor:pointer;color:var(--t3);display:flex;width:12px;height:12px" id="log-clear">' + I.x + '</span>' : '';
  return '<div class="page active" style="height:calc(100vh - 100px)">'
    + '<div class="logs-toolbar">'
    +   '<div class="logs-search">'
    +     '<span style="display:flex;width:12px;height:12px;color:var(--t3)">' + I.filter + '</span>'
    +     '<input type="text" id="log-search" placeholder="Filter logs..." value="' + esc(S.logFilter) + '">'
    +     clearX
    +   '</div>'
    +   '<button class="pill" onclick="document.getElementById(' + "'log-feed-full'" + ').innerHTML=' + "''" + ';S.logs=[]"><span style="display:flex;width:11px;height:11px">' + I.trash + '</span>Clear</button>'
    +   '<button class="pill" onclick="navigator.clipboard.writeText(S.logs.map(function(l){return l.raw}).join(' + "'\\n'" + '))"><span style="display:flex;width:11px;height:11px">' + I.copy + '</span>Copy</button>'
    +   '<button class="pill" onclick="br(' + "'openLogDir'" + ')"><span style="display:flex;width:11px;height:11px">' + I.folder + '</span>Open dir</button>'
    +   '<button class="pill" onclick="br(' + "'fetchMgmt'" + ')"><span style="display:flex;width:11px;height:11px">' + I.terminal + '</span>Mgmt log</button>'
    + '</div>'
    + '<div class="logs-body" id="log-feed-full"></div>'
    + '<div class="logs-foot">'
    +   '<span>' + S.logs.length + ' lines</span>'
    +   '<span>·</span><span>buffered to ~/.vpntray/logs/</span>'
    +   '<span>·</span><span style="color:var(--amber)">● live tail</span>'
    + '</div>'
    + '</div>';
}
function bindLogs() {
  const inp = document.getElementById('log-search');
  if (inp) inp.oninput = e => { S.logFilter = e.target.value; flushLogToDom(); };
  const cl = document.getElementById('log-clear');
  if (cl) cl.onclick = () => { S.logFilter = ''; renderPage(); };
  flushLogToDom();
}

// ── settings page ──────────────────────────────────────────────────
function pageSettings() {
  return '<div class="page active">'
    + '<div class="card">'
    +   '<div class="card-head"><div class="card-head-l"><span class="card-title">STARTUP</span></div></div>'
    +   tog('ov-autocon', !!S.settings.auto_connect, 'Auto-connect last profile on login', 'connects 2s after the tray initialises')
    +   tog('ov-recon',   S.settings.reconnect !== false, 'Auto-reconnect on drop', '--connect-retry. respects --keepalive timeouts')
    +   '<div class="mono" style="display:flex;align-items:center;gap:10px;font-size:11px;color:var(--t2);padding-left:42px;margin-top:4px">'
    +     '<span>Retry delay:</span>'
    +     '<input type="number" class="inp" id="ov-rd" value="' + (S.settings.reconnect_delay || 5) + '" style="width:64px;padding:4px 8px;text-align:center">'
    +     '<span>seconds</span>'
    +   '</div>'
    + '</div>'
    + '<div class="card">'
    +   '<div class="card-head"><div class="card-head-l"><span class="card-title">EXTRA DIRECTIVES</span></div></div>'
    +   field('APPENDED TO OPENVPN ARGS', '<textarea class="inp" id="ov-extra" rows="3" placeholder="--sndbuf 393216&#10;--rcvbuf 393216&#10;--mssfix 1450"></textarea>')
    + '</div>'
    + '<div class="card">'
    +   '<div class="card-head"><div class="card-head-l"><span class="card-title">SYSTEM</span></div></div>'
    +   '<div class="sys">'
    +     '<div class="sys-row"><span class="sys-key">OpenVPN</span><span>' + esc(S.sysInfo) + '</span></div>'
    +     '<div class="sys-row"><span class="sys-key">Profiles dir</span><span>~/.vpntray/profiles/</span></div>'
    +     '<div class="sys-row"><span class="sys-key">Logs dir</span><span>~/.vpntray/logs/</span></div>'
    +     '<div class="sys-row"><span class="sys-key">Mgmt iface</span><span>127.0.0.1:17505 (token-auth)</span></div>'
    +   '</div>'
    + '</div>'
    + '</div>';
}

// ── form helpers ───────────────────────────────────────────────────
function field(label, html) { return '<div class="field"><span class="fl">' + label + '</span>' + html + '</div>'; }
function selOpts(id, opts) { return '<select class="inp" id="' + id + '">' + opts.map(o => '<option>' + esc(o) + '</option>').join('') + '</select>'; }
function tog(id, on, label, sub) {
  return '<label class="tog">'
    + '<input type="checkbox" id="' + id + '"' + (on ? ' checked' : '') + ' style="display:none">'
    + '<span class="tog-track' + (on ? ' on' : '') + '"><span class="tog-knob"></span></span>'
    + '<div><div class="tog-label">' + label + '</div>' + (sub ? '<div class="tog-sub">' + sub + '</div>' : '') + '</div>'
    + '</label>';
}
function bindOverrides() {
  document.querySelectorAll('.tog').forEach(el => {
    el.onclick = () => {
      const cb = el.querySelector('input[type=checkbox]');
      cb.checked = !cb.checked;
      el.querySelector('.tog-track').classList.toggle('on', cb.checked);
      gatherOverrides();
    };
  });
  document.querySelectorAll('.inp').forEach(el => {
    el.addEventListener('change', gatherOverrides);
    el.addEventListener('blur',   gatherOverrides);
  });
}

// gather only the keys whose corresponding DOM elements are currently in
// the page, then merge into S.overrides. this avoids wiping a setting (e.g.
// killswitch) when the user navigates to a page that doesn't include it.
function gatherOverrides() {
  const FIELDS = [
    ['proto','ov-proto','str'], ['cipher','ov-cipher','str'], ['auth','ov-auth','str'], ['compress','ov-comp','str'],
    ['dev_type','ov-dev','str'], ['tls_version_min','ov-tls','str'], ['verbosity','ov-verb','str'], ['redirect_gw','ov-rg','str'],
    ['tun_mtu','ov-mtu','num'], ['fragment','ov-frag','num'], ['mssfix','ov-mss','num'], ['port','ov-port','num'],
    ['keepalive_interval','ov-ki','num'], ['keepalive_timeout','ov-kt','num'], ['ping','ov-ping','num'], ['ping_restart','ov-pr','num'],
    ['reneg_sec','ov-reneg','num'], ['sndbuf','ov-sndbuf','num'], ['rcvbuf','ov-rcvbuf','num'], ['txqueuelen','ov-txq','num'],
    ['float','ov-float','bool'], ['nobind','ov-nobind','bool'], ['killswitch','ov-ks','bool'], ['dns_fix','ov-dns','bool'],
    ['auth_user_pass','ov-authfile','str'], ['pull_filter','ov-pf','str'],
    ['proxy_type','ov-px','str'], ['proxy_host','ov-pxh','str'], ['proxy_port','ov-pxp','num'], ['proxy_auth_file','ov-pxa','str'],
    ['route_nopull','ov-rnp','bool'], ['custom_routes','ov-routes','str'],
    ['reconnect','ov-recon','bool'], ['reconnect_delay','ov-rd','num'], ['extra_directives','ov-extra','str'],
    ['auto_connect','ov-autocon','bool'],
  ];
  const updates = {};
  for (const [key, id, type] of FIELDS) {
    const e = document.getElementById(id);
    if (!e) continue;
    if (type === 'bool') updates[key] = e.checked;
    else if (type === 'num') updates[key] = e.value ? parseInt(e.value) : null;
    else updates[key] = e.value;
  }
  Object.assign(S.overrides, updates);
  S.overrides.theme = S.theme;
  br('setOverrides', S.overrides);
  // mirror to settings cache for toggle visuals after re-render
  if ('killswitch' in updates)      S.settings.killswitch = !!updates.killswitch;
  if ('dns_fix' in updates)         S.settings.dns_fix = !!updates.dns_fix;
  if ('reconnect' in updates)       S.settings.reconnect = !!updates.reconnect;
  if ('auto_connect' in updates)    S.settings.auto_connect = !!updates.auto_connect;
  if ('reconnect_delay' in updates && updates.reconnect_delay) S.settings.reconnect_delay = updates.reconnect_delay;
}

// ── connect/disconnect ─────────────────────────────────────────────
function doConnect() {
  if (!S.profiles.length) return;
  if (!S.selected) S.selected = S.profiles[0].name;
  gatherOverrides();
  const p = S.profiles.find(x => x.name === S.selected) || S.profiles[0];
  br('connect', { path: p.path, name: p.name });
}
function doDisconnect() { br('disconnect'); }

// ── log feed ───────────────────────────────────────────────────────
function classifyLog(t) {
  if (t.indexOf('Completed') > -1 || t.indexOf('[+]') > -1) return 'ok';
  if (t.indexOf('[!]') > -1 || t.indexOf('Error') > -1 || t.indexOf('AUTH_FAILED') > -1) return 'err';
  if (t.indexOf('[*]') > -1 || t.indexOf('WARNING') > -1) return 'warn';
  if (t.indexOf('VERIFY') > -1 || t.indexOf('PUSH') > -1 || t.indexOf('TLS') > -1) return 'info';
  return '';
}
function logGlyph(k) { return k === 'ok' ? '✓' : k === 'warn' ? '!' : k === 'err' ? '✗' : '·'; }
function logLineHTML(l) {
  return '<div class="log-line log-' + (l.k || '') + '"><span class="log-ts">' + esc(l.ts) + '</span><span class="log-glyph">' + logGlyph(l.k) + '</span><span class="log-text">' + esc(l.body) + '</span></div>';
}
function flushLogToDom() {
  const filtered = S.logFilter
    ? S.logs.filter(l => l.raw.toLowerCase().indexOf(S.logFilter.toLowerCase()) > -1)
    : S.logs;
  const prev = document.getElementById('log-prev');
  if (prev) {
    prev.innerHTML = filtered.slice(0, 8).map(logLineHTML).join('');
    prev.scrollTop = 0;
  }
  const full = document.getElementById('log-feed-full');
  if (full) {
    full.innerHTML = filtered.map(logLineHTML).join('');
    full.scrollTop = 0;
  }
}

// ── python -> js callbacks ─────────────────────────────────────────
function onProfiles(list) {
  S.profiles = list;
  if (!S.selected || !list.find(p => p.name === S.selected)) {
    S.selected = list.length ? list[0].name : null;
  }
  if (S.page === 'connect' || S.page === 'profiles') renderPage();
  renderTopbar();
}
function onStatus(payload) {
  S.vpnState = payload.state;
  S.profile = payload.profile || '';
  S.connectedAt = payload.connected_at ? new Date(payload.connected_at) : null;
  if (S.vpnState !== 'connected') {
    S.bytesIn = 0; S.bytesOut = 0; S.rateIn = 0; S.rateOut = 0;
    S.latency = -1; S.localIp = ''; S.remoteIp = ''; S.tunDev = '';
    S.throughputHist = S.throughputHist.map(() => ({ down:0, up:0 }));
    S.latencyHist    = S.latencyHist.map(() => ({ v:0 }));
  }
  renderSidebarFoot(); renderTopbar(); renderBrandMark();
  if (S.page === 'connect' || S.page === 'profiles') renderPage();
}
function onStats(d) {
  S.bytesIn  = d.bytes_in  || 0;
  S.bytesOut = d.bytes_out || 0;
  S.rateIn   = d.rate_in   || 0;
  S.rateOut  = d.rate_out  || 0;
  S.localIp  = d.local_ip  || '';
  S.remoteIp = d.remote_ip || '';
  S.tunDev   = d.tun_dev   || '';
  if (typeof d.latency_ms === 'number') S.latency = d.latency_ms;

  S.throughputHist.push({ down: S.rateIn, up: S.rateOut });
  if (S.throughputHist.length > 48) S.throughputHist.shift();
  S.latencyHist.push({ v: S.latency > 0 ? S.latency : 0 });
  if (S.latencyHist.length > 48) S.latencyHist.shift();

  // surgical updates only — touching the globe SVG would restart all SMIL
  // animations every tick and kill them before they finish a cycle.
  if (S.page === 'connect') {
    setTxt('m-dl', fmtBytes(S.bytesIn));
    setTxt('m-dl-sub', S.vpnState === 'connected' ? fmtRate(S.rateIn) : '');
    setTxt('m-ul', fmtBytes(S.bytesOut));
    setTxt('m-ul-sub', S.vpnState === 'connected' ? fmtRate(S.rateOut) : '');
    setTxt('m-lat', S.vpnState === 'connected' && S.latency >= 0 ? Math.round(S.latency) + ' ms' : '—');
    setTxt('m-ep',  S.vpnState === 'connected' && S.remoteIp ? S.remoteIp : '—');
    setTxt('m-ep-sub', S.vpnState === 'connected' && S.tunDev ? S.tunDev : '');
    refreshSparks();
    const ls = document.getElementById('spark-lat-sub');
    if (ls) ls.textContent = '· ' + (S.vpnState === 'connected' && S.latency >= 0 ? Math.round(S.latency) + 'ms current' : '—');
  }
  renderTopbar();
}
function onSettings(s) {
  Object.assign(S.settings, s);
  ['killswitch','dns_fix','reconnect','reconnect_delay','auto_connect','theme'].forEach(k => {
    if (k in s) S.overrides[k] = s[k];
  });
  if (s.theme) applyTheme(s.theme);
  if (S.page === 'security' || S.page === 'settings') renderPage();
  renderTopbar(); renderBrandMark();
}
function onVersion(v) { S.sysInfo = v; if (S.page === 'settings') renderPage(); }
function onConfig(text) { showConfigModal(text); }
function appendLog(line) {
  const m = line.match(/^\[(\d{2}:\d{2}:\d{2})\]\s?(.*)$/);
  const ts = m ? m[1] : '';
  const body = m ? m[2] : line;
  S.logs.unshift({ ts, body, k: classifyLog(body), raw: line });
  if (S.logs.length > 1000) S.logs.length = 1000;
  flushLogToDom();
}

// uptime ticker — drives only the UPTIME card. connectedAt lands once on
// state change and we do local clock math instead of poking python every sec.
setInterval(() => {
  if (!S.connectedAt) return;
  const sec = Math.floor((Date.now() - S.connectedAt.getTime()) / 1000);
  setTxt('m-up', fmtUptime(Math.max(0, sec)));
}, 1000);

// ── modals ─────────────────────────────────────────────────────────
function modalConfirm(msg, cb) {
  const o = document.createElement('div');
  o.className = 'modal-bg';
  o.innerHTML = '<div class="modal"><div class="modal-sub">' + esc(msg) + '</div><div class="modal-foot"><button class="modal-btn" data-no>Cancel</button><button class="modal-btn danger" data-yes>OK</button></div></div>';
  document.body.appendChild(o);
  const close = v => { o.remove(); cb(v); };
  o.querySelector('[data-yes]').onclick = () => close(true);
  o.querySelector('[data-no]').onclick  = () => close(false);
  o.onclick = e => { if (e.target === o) close(false); };
}
function modalPrompt(msg, def, cb) {
  const o = document.createElement('div');
  o.className = 'modal-bg';
  o.innerHTML = '<div class="modal"><div class="modal-sub">' + esc(msg) + '</div><input class="inp" id="mp-in" style="margin-bottom:6px"><div class="modal-foot"><button class="modal-btn" data-no>Cancel</button><button class="modal-btn primary" data-yes>OK</button></div></div>';
  document.body.appendChild(o);
  const inp = o.querySelector('#mp-in');
  inp.value = def || '';
  setTimeout(() => { inp.focus(); inp.select(); }, 50);
  const close = v => { o.remove(); cb(v); };
  o.querySelector('[data-yes]').onclick = () => close(inp.value);
  o.querySelector('[data-no]').onclick  = () => close(null);
  inp.addEventListener('keydown', e => { if (e.key === 'Enter') close(inp.value); else if (e.key === 'Escape') close(null); });
}
function showConfigModal(text) {
  const o = document.createElement('div');
  o.className = 'modal-bg';
  o.innerHTML = '<div class="modal" style="width:90%;max-width:760px"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px"><span class="modal-title">CONFIG</span><div style="display:flex;gap:6px"><button class="modal-btn" data-copy>Copy</button><button class="modal-btn danger" data-close>Close</button></div></div><pre id="cfg-body"></pre></div>';
  document.body.appendChild(o);
  o.querySelector('#cfg-body').textContent = text;
  const close = () => o.remove();
  o.querySelector('[data-close]').onclick = close;
  o.querySelector('[data-copy]').onclick  = () => navigator.clipboard.writeText(text);
  o.onclick = e => { if (e.target === o) close(); };
  document.addEventListener('keydown', function k(e) { if (e.key === 'Escape') { close(); document.removeEventListener('keydown', k); } });
}
function promptAuth(name) {
  const o = document.createElement('div');
  o.className = 'modal-bg';
  o.id = 'au-modal';
  o.innerHTML = '<div class="modal" style="min-width:380px">'
    + '<div class="modal-title">CREDENTIALS</div>'
    + '<div class="modal-sub">' + esc(name) + '</div>'
    + '<div class="field" style="margin-bottom:10px"><span class="fl">USERNAME</span><input class="inp" id="au-u" autocomplete="off" autocapitalize="off" spellcheck="false"></div>'
    + '<div class="field" style="margin-bottom:10px"><span class="fl">PASSWORD</span><input class="inp" id="au-p" type="password"></div>'
    + '<label class="cb"><input type="checkbox" id="au-r" style="accent-color:var(--amber)"><span>Remember on this machine (saved with mode 0600)</span></label>'
    + '<div class="modal-foot"><button class="modal-btn" data-no>Cancel</button><button class="modal-btn primary" data-yes>Connect</button></div>'
    + '</div>';
  document.body.appendChild(o);
  setTimeout(() => document.getElementById('au-u').focus(), 50);
  let done = false;
  const submit = () => {
    if (done) return;
    const u = document.getElementById('au-u').value;
    const p = document.getElementById('au-p').value;
    const r = document.getElementById('au-r').checked;
    if (!u) { document.getElementById('au-u').focus(); return; }
    done = true;
    br('submitAuth', { username: u, password: p, remember: r });
    o.remove();
  };
  const cancel = () => { if (done) return; done = true; br('cancelAuth', {}); o.remove(); };
  o.querySelector('[data-yes]').onclick = submit;
  o.querySelector('[data-no]').onclick  = cancel;
  ['au-u','au-p'].forEach(id => {
    document.getElementById(id).addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); submit(); } });
  });
  document.addEventListener('keydown', function k(e) { if (e.key === 'Escape') { cancel(); document.removeEventListener('keydown', k); } });
}

// ── init ───────────────────────────────────────────────────────────
function init() {
  applyTheme(S.theme);
  renderNav();
  renderBrandMark();
  renderSidebarFoot();
  renderTopbar();
  renderPage();
  setTimeout(() => br('init'), 250);
}
document.addEventListener('DOMContentLoaded', init);
</script>
</body></html>"""


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] vpntray needs root for openvpn. run: sudo python3 vpntray.py")
        sys.exit(1)
    VPNTrayApp().run()
