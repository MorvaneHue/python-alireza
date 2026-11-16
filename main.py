#!/usr/bin/env python3
# ------------------------------------------------------------------ #
# 3x-ui-katabump  -  MHSanaei 3x-ui + Xray + Sub behind 1 port        #
# Python edition: main.py + requirements.txt.  Standard library only. #
# (1:1 port of the two-file Node.js edition index.js + package.json)  #
#                                                                     #
# Layout under the KataBump root (persistent):                        #
#   3x-ui/app        x-ui binary & helper scripts                     #
#   3x-ui/bin        xray-core + mtg + geoip/geosite assets           #
#   3x-ui/data       SQLite database x-ui.db (persistent!)            #
#   3x-ui/certs      self-signed TLS cert for optional TLS inbounds   #
#   3x-ui/log        panel & xray logs                                #
#   3x-ui/PANEL.txt  saved credentials, links, and subscription URL   #
# ------------------------------------------------------------------ #

import asyncio
import base64
import gc
import http.client
import json
import math
import os
import platform
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tarfile
import threading
import time
import urllib.parse

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass


def release_memory():
    try:
        gc.collect()
    except Exception:
        pass


# ------------------------------ config ---------------------------- #

WRAPPER = "3x-ui-katabump-1.0"
UA = "3x-ui-katabump/1.0"
REPO = "MHSanaei/3x-ui"


def parse_int(v, dflt):
    """Same behaviour as JS parseInt(v, 10) with a default for NaN."""
    if v is None:
        return dflt
    m = re.match(r"^\s*([+-]?\d+)", str(v))
    if not m:
        return dflt
    return int(m.group(1))


ENV = os.environ

XUI_VERSION = ENV.get("XUI_VERSION") or "v3.10.2"
STATUS_PATH = "/_kb/status"
TUNNEL_DEFAULT = "vless:/vless-ws:21001,vless:/mb-vless:21001"
DEFAULT_INBOUND_REMARK = ENV.get("XUI_INBOUND_REMARK") or "Katabump-VLESS-WS"
DEFAULT_CLIENT_EMAIL = ENV.get("XUI_CLIENT_EMAIL") or "katabump"
ADMIN_USER = ENV.get("ADMIN_USER") or "admin"
ADMIN_PASS = ENV.get("ADMIN_PASS") or ""

ROOT = ENV.get("KATABUMP_ROOT") or ENV.get("KATABUMP_DIR") or os.getcwd()
BASE = os.path.join(ROOT, "3x-ui")
APP = os.path.join(BASE, "app")
BIN_DIR = os.path.join(BASE, "bin")
DATA = os.path.join(BASE, "data")
CERT_DIR = os.path.join(BASE, "certs")
LOGS = os.path.join(BASE, "log")
TMP = os.path.join(BASE, "tmp")
STATE_FILE = os.path.join(BASE, "state.json")
CRED_FILE = os.path.join(BASE, "PANEL.txt")
VERSION_FILE = os.path.join(APP, ".version")

SKIP_XRAY = ENV.get("XUI_SKIP_XRAY") == "1"
FORCE_SETUP = ENV.get("XUI_FORCE_SETUP") == "1"
KEEP_RU_DAT = ENV.get("XUI_KEEP_RU_DAT") == "1"
AUTO_HOST_SYNC = ENV.get("XUI_AUTO_HOST_SYNC") != "0"
PANEL_MEM_MAX = parse_int(ENV.get("XUI_PANEL_MEM_MAX"), 225)  # MB ceiling before graceful restart
PUBLIC_HOST_ENV = (
    ENV.get("XUI_PUBLIC_HOST")
    or ENV.get("PASARGUARD_PUBLIC_HOST")
    or ENV.get("PUBLIC_HOST")
    or ""
).strip()

# ------------------------------ ports ----------------------------- #

PUBLIC_PORT = parse_int(ENV.get("SERVER_PORT") or ENV.get("PORT"), 3000)
PANEL_PORT = parse_int(ENV.get("PANEL_PORT"), 2053)
SUB_PORT = parse_int(ENV.get("SUB_PORT"), 2096)
XRAY_PORT = parse_int(ENV.get("XUI_XRAY_PORT") or ENV.get("PASARGUARD_XRAY_PORT"), 21001)


def first_free_port(candidates):
    for port in candidates:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            try:
                s.close()
            except Exception:
                pass
    return candidates[-1]


def parse_tunnels(spec):
    out = []
    for raw in re.split(r"[,\n]", str(spec or "")):
        p = raw.strip().split(":")
        if len(p) < 3:
            continue
        port = parse_int(p[2], 0)
        if not p[1] or not port:
            continue
        out.append(
            {
                "proto": (p[0] or "vless").lower(),
                "path": p[1] if p[1].startswith("/") else "/" + p[1],
                "port": port,
                "source": "static",
            }
        )
    if not out:
        out.append({"proto": "vless", "path": "/vless-ws", "port": 21001, "source": "static"})
        out.append({"proto": "vless", "path": "/mb-vless", "port": 21001, "source": "static"})
    return out


TUNNELS = parse_tunnels(ENV.get("XUI_TUNNELS") or ENV.get("PASARGUARD_TUNNELS") or TUNNEL_DEFAULT)

# Dynamic routing state populated from 3x-ui's active inbounds & settings
DYNAMIC_ROUTES = {
    "subPaths": ["/sub/", "/json/", "/clash/"],
    "pathRoutes": [],  # [{ path, port, proto, remark, network }]
    "wsDefaultPort": 0,
    "tlsRoutes": [],  # [{ sni, port, proto, remark }]
    "rawTcpPort": 0,
}

# ------------------------------ logging --------------------------- #

STATE = {
    "wrapper": WRAPPER,
    "xui": None,
    "xray": None,
    "publicPort": PUBLIC_PORT,
    "panelPort": PANEL_PORT,
    "subPort": SUB_PORT,
    "panelUp": False,
    "subUp": False,
    "coreUp": False,
    "step": "booting",
    "error": None,
    "admin": None,
    "publicHost": None,
    "tunnels": TUNNELS,
    "inbounds": [],
    "shareLink": None,
    "subUrl": None,
    "subJsonUrl": None,
    "data": DATA,
}

C = sys.stdout.isatty() or ENV.get("FORCE_COLOR") == "1"


def paint(c, s):
    return "\x1b[%sm%s\x1b[0m" % (c, s) if C else s


def _out(*a):
    print(*a, flush=True)


def log(*a):
    _out("[3x-ui]", *a)


def ok(*a):
    _out(paint("32", "  ✓"), *a)


def warn(*a):
    _out(paint("33", "  !"), *a)


def err(*a):
    _out(paint("31", "  ✗"), *a)


def step(s):
    STATE["step"] = s
    _out(paint("36", "  ›"), s)


def fmt_bytes(n):
    if n >= 1e9:
        return "%.1f GB" % (n / 1e9)
    if n >= 1e6:
        return "%.1f MB" % (n / 1e6)
    if n >= 1e3:
        return "%d KB" % round(n / 1e3)
    return "%d B" % n


def random_token(length):
    raw = base64.b64encode(os.urandom(int(math.ceil(length * 0.75)))).decode("ascii")
    return re.sub(r"[+/=]", "", raw)[:length]


def random_lower_num(length):
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    b = os.urandom(length)
    return "".join(chars[b[i] % len(chars)] for i in range(length))


def uuid4():
    b = bytearray(os.urandom(16))
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    h = bytes(b).hex()
    return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:])


def jdumps(obj):
    """Compact JSON, like JS JSON.stringify(obj)."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def jdumps_pretty(obj):
    """Indented JSON, like JS JSON.stringify(obj, null, 2)."""
    return json.dumps(obj, indent=2, ensure_ascii=False)


# ------------------------------ state ----------------------------- #


def read_state():
    try:
        with open(STATE_FILE, "r", encoding="utf8") as f:
            v = json.load(f)
        return v if isinstance(v, dict) else {}
    except Exception:
        return {}


def save_state(patch):
    try:
        cur = read_state()
        cur.update(patch)
        cur["at"] = int(time.time() * 1000)
        with open(STATE_FILE, "w", encoding="utf8") as f:
            f.write(jdumps_pretty(cur))
    except Exception:
        pass


def ensure_dir(p):
    os.makedirs(p, exist_ok=True)


def ensure_dirs():
    for d in (BASE, APP, BIN_DIR, DATA, CERT_DIR, LOGS, TMP):
        ensure_dir(d)


def rmrf(p):
    try:
        if os.path.islink(p) or os.path.isfile(p):
            os.unlink(p)
        elif os.path.isdir(p):
            shutil.rmtree(p, ignore_errors=True)
    except Exception:
        pass


# ------------------------------ http ------------------------------ #


def _ssl_context():
    # System CA store first (honours SSL_CERT_FILE etc.). If the optional `certifi`
    # package is installed its bundle is added on top, which helps on slim images
    # that ship without ca-certificates.
    ctx = ssl.create_default_context()
    try:
        import certifi

        ctx.load_verify_locations(cafile=certifi.where())
    except Exception:
        pass
    return ctx


_SSL_CTX = None


def _connection(u, timeout):
    global _SSL_CTX
    https = u.scheme == "https"
    port = u.port or (443 if https else 80)
    if https:
        if _SSL_CTX is None:
            _SSL_CTX = _ssl_context()
        return http.client.HTTPSConnection(u.hostname, port, timeout=timeout, context=_SSL_CTX)
    return http.client.HTTPConnection(u.hostname, port, timeout=timeout)


def _path_of(u):
    p = u.path or "/"
    if u.query:
        p += "?" + u.query
    return p


class Resp:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body


def _request_sync(url, method=None, headers=None, body=None, timeout=30, redirects=0):
    try:
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError("bad url")
    except Exception:
        raise RuntimeError("bad url " + str(url))
    payload = body.encode("utf8") if isinstance(body, str) else body
    hdrs = {"User-Agent": UA}
    hdrs.update(headers or {})
    if payload:
        hdrs["Content-Length"] = str(len(payload))
    meth = method or ("POST" if payload else "GET")
    conn = _connection(u, timeout)
    try:
        conn.request(meth, _path_of(u), body=payload if payload else None, headers=hdrs)
        res = conn.getresponse()
        loc = res.getheader("Location")
        if 300 <= res.status < 400 and loc:
            res.read()
            if redirects > 6:
                raise RuntimeError("too many redirects")
            nxt = urllib.parse.urljoin(url, loc)
            conn.close()
            return _request_sync(nxt, meth, headers, body, timeout, redirects + 1)
        data = res.read()
        hmap = {k.lower(): v for k, v in res.getheaders()}
        return Resp(res.status, hmap, data)
    finally:
        try:
            conn.close()
        except Exception:
            pass


async def request(url, method=None, headers=None, body=None, timeout=30):
    return await asyncio.to_thread(_request_sync, url, method, headers, body, timeout)


def _download_sync(url, dest, label):
    tmp = dest + ".part"
    rmrf(tmp)
    done = 0
    last = 0.0
    target = url
    redirects = 0
    while True:
        try:
            u = urllib.parse.urlsplit(target)
            if u.scheme not in ("http", "https") or not u.hostname:
                raise ValueError("bad url")
        except Exception:
            raise RuntimeError("bad url " + str(target))
        conn = _connection(u, 180)
        try:
            conn.request("GET", _path_of(u), headers={"User-Agent": UA})
            res = conn.getresponse()
            loc = res.getheader("Location")
            if 300 <= res.status < 400 and loc:
                res.read()
                if redirects > 6:
                    raise RuntimeError("%s: too many redirects" % label)
                target = urllib.parse.urljoin(target, loc)
                redirects += 1
                continue
            if res.status != 200:
                raise RuntimeError("%s: HTTP %d" % (label, res.status))
            total = parse_int(res.getheader("Content-Length"), 0)
            with open(tmp, "wb") as out:
                while True:
                    chunk = res.read(1 << 18)
                    if not chunk:
                        break
                    out.write(chunk)
                    done += len(chunk)
                    now = time.time()
                    if now - last > 3.5:
                        last = now
                        sys.stdout.write(
                            "\r  … %s %s%s   "
                            % (label, fmt_bytes(done), (" / " + fmt_bytes(total)) if total else "")
                        )
                        sys.stdout.flush()
            if total and done < total * 0.98:
                raise RuntimeError("%s: truncated" % label)
            sys.stdout.write("\r  … %s %s          \n" % (label, fmt_bytes(done)))
            sys.stdout.flush()
            break
        finally:
            try:
                conn.close()
            except Exception:
                pass
    os.rename(tmp, dest)
    return os.path.getsize(dest)


async def download_file(url, dest, label):
    return await asyncio.to_thread(_download_sync, url, dest, label)


# ------------------------------ tar ------------------------------- #


def safe_join(dest_dir, name):
    norm = os.path.normpath(name)
    norm = re.sub(r"^(\.\.[/\\])+", "", norm)
    full = os.path.join(dest_dir, norm)
    if not full.startswith(os.path.abspath(dest_dir)):
        return None
    return full


def _extract_tar_gz_sync(gz_path, dest_dir, strip=0, filter_fn=None):
    os.makedirs(dest_dir, exist_ok=True)
    count = 0
    with tarfile.open(gz_path, "r|gz") as tf:
        for m in tf:
            name = m.name
            if strip:
                parts = name.split("/")
                if len(parts) <= strip:
                    continue
                name = "/".join(parts[strip:])
            if not name or name == "." or name == "./":
                continue
            if filter_fn and not filter_fn(name):
                continue
            target = safe_join(dest_dir, name)
            if not target:
                continue

            if m.isdir():
                os.makedirs(target, exist_ok=True)
            elif m.isreg():
                os.makedirs(os.path.dirname(target), exist_ok=True)
                src = tf.extractfile(m)
                with open(target, "wb") as out:
                    if src is not None:
                        shutil.copyfileobj(src, out, 1 << 18)
                if m.mode & 0o111:
                    try:
                        os.chmod(target, 0o755)
                    except Exception:
                        pass
                count += 1
            elif m.issym():
                try:
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    try:
                        os.unlink(target)
                    except Exception:
                        pass
                    os.symlink(m.linkname, target)
                except Exception:
                    try:
                        src = safe_join(dest_dir, m.linkname)
                        if src and os.path.exists(src):
                            shutil.copyfile(src, target)
                    except Exception:
                        pass
            elif m.islnk():
                try:
                    src = safe_join(dest_dir, m.linkname)
                    if src:
                        os.link(src, target)
                except Exception:
                    pass
    return count


async def extract_tar_gz(gz_path, dest_dir, strip=0, filter_fn=None):
    os.makedirs(TMP, exist_ok=True)
    return await asyncio.to_thread(_extract_tar_gz_sync, gz_path, dest_dir, strip, filter_fn)


# ------------------------------ shell ----------------------------- #


async def run(cmd, args, cwd=None, env=None, timeout=None, quiet=True):
    full_env = dict(os.environ)
    full_env.update(env or {})
    try:
        proc = await asyncio.create_subprocess_exec(
            cmd,
            *args,
            cwd=cwd or APP,
            env=full_env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except Exception as e:
        return {"code": 127, "out": "\n" + str(e)}
    try:
        if timeout:
            data, _ = await asyncio.wait_for(proc.communicate(), timeout)
        else:
            data, _ = await proc.communicate()
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        data, _ = await proc.communicate()
    out = (data or b"").decode("utf8", errors="replace")
    if len(out) > 65536:
        out = out[-49152:]
    if quiet is False:
        sys.stdout.write(out)
        sys.stdout.flush()
    code = proc.returncode
    if code is None or code < 0:
        code = 1
    return {"code": code, "out": out}


# ---------------------------- utilities --------------------------- #


async def port_open(port, timeout=1.2):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout)
    except Exception:
        return False
    try:
        w.close()
    except Exception:
        pass
    return True


async def detect_public_ip():
    if PUBLIC_HOST_ENV:
        return PUBLIC_HOST_ENV
    saved = read_state().get("publicHost")
    endpoints = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ident.me",
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com",
    ]
    for u in endpoints:
        try:
            r = await request(u, timeout=6)
            ip = r.body.decode("utf8", errors="replace").strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                return ip
        except Exception:
            pass
    return saved or None


def kill_orphans():
    try:
        me = os.getpid()
        for entry in os.listdir("/proc"):
            if not re.match(r"^\d+$", entry):
                continue
            pid = int(entry)
            if pid == me or pid <= 1:
                continue
            try:
                with open("/proc/%d/cmdline" % pid, "rb") as f:
                    argv0 = f.read().decode("utf8", errors="replace").split("\0")[0] or ""
            except Exception:
                continue
            if (
                argv0.endswith("/3x-ui/app/x-ui")
                or "/3x-ui/bin/xray-" in argv0
                or "/3x-ui/bin/mtg-" in argv0
            ):
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass
    except Exception:
        pass


def rss_of(pid):
    try:
        with open("/proc/%d/statm" % pid, "r") as f:
            s = f.read().split(" ")
        return (int(s[1]) * 4096) / 1048576  # resident pages -> MB
    except Exception:
        return 0


def tail_file(file, lines):
    try:
        with open(file, "r", encoding="utf8", errors="replace") as f:
            s = f.read()
        return "\n".join(s.split("\n")[-lines:])
    except Exception:
        return "(no log)"


# -------------------------- 3x-ui binary -------------------------- #


def node_arch():
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "x64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    if m.startswith("armv7") or m.startswith("armv6") or m == "arm":
        return "arm"
    if m in ("i386", "i486", "i586", "i686", "x86"):
        return "ia32"
    return m


def arch_asset():
    m = node_arch()
    if m == "x64":
        return {"tar": "x-ui-linux-amd64.tar.gz", "xray": "xray-linux-amd64"}
    if m == "arm64":
        return {"tar": "x-ui-linux-arm64.tar.gz", "xray": "xray-linux-arm64"}
    if m == "arm":
        return {"tar": "x-ui-linux-armv7.tar.gz", "xray": "xray-linux-armv7"}
    if m == "ia32":
        return {"tar": "x-ui-linux-386.tar.gz", "xray": "xray-linux-386"}
    if m == "s390x":
        return {"tar": "x-ui-linux-s390x.tar.gz", "xray": "xray-linux-s390x"}
    raise RuntimeError("unsupported CPU architecture: " + m)


async def resolve_xui_release_tag():
    if XUI_VERSION != "latest":
        return XUI_VERSION
    try:
        r = await request("https://api.github.com/repos/%s/releases/latest" % REPO, timeout=15)
        if r.status == 200:
            d = json.loads(r.body.decode("utf8"))
            if d and d.get("tag_name"):
                return d["tag_name"]
    except Exception:
        pass
    return "v3.10.2"


def xui_env(extra=None):
    env = dict(os.environ)
    env.update(
        {
            "XUI_DB_FOLDER": DATA,
            "XUI_LOG_FOLDER": LOGS,
            "XUI_BIN_FOLDER": BIN_DIR,
            "XUI_SKIP_HSTS": "true",
            "XUI_GOGC": ENV.get("XUI_GOGC") or "35",
            "GOMEMLIMIT": ENV.get("GOMEMLIMIT") or "180MiB",
            "TZ": ENV.get("TZ") or "UTC",
        }
    )
    env.update(extra or {})
    return env


async def install_xui(force):
    a = arch_asset()
    tar, xray = a["tar"], a["xray"]
    xui_exe = os.path.join(APP, "x-ui")
    xray_exe = os.path.join(BIN_DIR, xray)
    tag = await resolve_xui_release_tag()

    current_ver = ""
    try:
        with open(VERSION_FILE, "r", encoding="utf8") as f:
            current_ver = f.read().strip()
    except Exception:
        pass

    if not force and os.path.exists(xui_exe) and os.path.exists(xray_exe) and current_ver == tag:
        ok("3x-ui %s present" % tag)
    else:
        step("downloading 3x-ui %s (%s)" % (tag, tar))
        gz_path = os.path.join(TMP, "x-ui.tar.gz")
        url = "https://github.com/%s/releases/download/%s/%s" % (REPO, tag, tar)
        await download_file(url, gz_path, "3x-ui %s" % tag)
        step("extracting 3x-ui & xray-core")

        def keep(entry_name):
            if not KEEP_RU_DAT and (entry_name.endswith("_RU.dat") or entry_name.endswith("_RU.db")):
                return False
            return True

        count = await extract_tar_gz(gz_path, APP, 1, keep)
        rmrf(gz_path)
        if not count or not os.path.exists(xui_exe):
            raise RuntimeError("3x-ui archive extraction failed")

        # Move bundled bin/* into persistent BIN_DIR while preserving any custom files
        extracted_bin = os.path.join(APP, "bin")
        if os.path.exists(extracted_bin):
            ensure_dir(BIN_DIR)
            for item in os.listdir(extracted_bin):
                src = os.path.join(extracted_bin, item)
                dst = os.path.join(BIN_DIR, item)
                try:
                    os.rename(src, dst)
                except Exception:
                    shutil.copyfile(src, dst)
                    rmrf(src)
            rmrf(extracted_bin)

        # Also keep a symlink APP/bin -> BIN_DIR in case anything references relative ./bin
        try:
            os.symlink(BIN_DIR, os.path.join(APP, "bin"))
        except Exception:
            pass

        try:
            os.chmod(xui_exe, 0o755)
        except Exception:
            pass
        for item in os.listdir(BIN_DIR):
            if item.startswith("xray-") or item.startswith("mtg-"):
                try:
                    os.chmod(os.path.join(BIN_DIR, item), 0o755)
                except Exception:
                    pass
        with open(VERSION_FILE, "w", encoding="utf8") as f:
            f.write(tag + "\n")
        ok("3x-ui %s installed" % tag)

    v_panel = await run(xui_exe, ["-v"], quiet=True, timeout=15, env=xui_env())
    first = (v_panel["out"] or "").strip().split("\n")[0]
    STATE["xui"] = first or tag

    if os.path.exists(xray_exe):
        v_xray = await run(xray_exe, ["version"], quiet=True, timeout=15)
        first = (v_xray["out"] or "").strip().split("\n")[0]
        STATE["xray"] = first or xray
    return {"xuiExe": xui_exe, "xrayExe": xray_exe}


# ------------------------- runtime & api -------------------------- #

CHILD = {"panel": None, "log": None}


def start_panel_process(xui_exe):
    fd = open(os.path.join(LOGS, "panel.log"), "ab")
    child = subprocess.Popen(
        [xui_exe, "run"],
        cwd=APP,
        env=xui_env(),
        stdin=subprocess.DEVNULL,
        stdout=fd,
        stderr=fd,
    )

    def _waiter():
        code = child.wait()
        log("3x-ui panel exited (code %s)" % code)

    threading.Thread(target=_waiter, daemon=True).start()
    old = CHILD.get("log")
    CHILD["panel"] = child
    CHILD["log"] = fd
    if old:
        try:
            old.close()
        except Exception:
            pass
    return child


def panel_exited():
    p = CHILD["panel"]
    return p is not None and p.poll() is not None


def panel_running():
    p = CHILD["panel"]
    return p is not None and p.poll() is None


async def wait_for_panel(timeout=120.0):
    started = time.time()
    while time.time() - started < timeout:
        if panel_exited():
            tail = tail_file(os.path.join(LOGS, "panel.log"), 30)
            raise RuntimeError("3x-ui exited during startup:\n" + tail)
        if await port_open(PANEL_PORT, 1.0):
            try:
                r = await request("http://127.0.0.1:%d/" % PANEL_PORT, timeout=3)
                if 200 <= r.status < 500:
                    return True
            except Exception:
                pass
        await asyncio.sleep(0.6)
    raise RuntimeError(
        "3x-ui did not become ready in time:\n" + tail_file(os.path.join(LOGS, "panel.log"), 30)
    )


def strong_password(seed):
    base = seed if (seed and len(seed) >= 8) else "Katabump" + random_token(6)
    p = re.sub(r"[^A-Za-z0-9!@#$%^&*_\-]", "", base)
    if not re.search(r"[A-Z]", p):
        p += "AB"
    if len(re.sub(r"[^A-Z]", "", p)) < 2:
        p += "CD"
    if len(re.sub(r"[^0-9]", "", p)) < 2:
        p += "19" + str(len(p) % 10) + "8"
    if not re.search(r"[!@#$%^&*_\-]", p):
        p += "!"
    if len(p) < 12:
        p += "Kb" + random_token(4) + "9"
    return p[:40]


async def configure_cli_settings(xui_exe):
    st = read_state()
    user = ADMIN_USER
    password = ADMIN_PASS or st.get("adminPass") or strong_password("Katabump" + random_token(5))

    step("configuring 3x-ui panel credentials & port")
    r = await run(
        xui_exe,
        [
            "setting",
            "-username",
            user,
            "-password",
            password,
            "-port",
            str(PANEL_PORT),
            "-webBasePath",
            "/",
            "-listenIP",
            "127.0.0.1",
        ],
        quiet=True,
        timeout=30,
        env=xui_env(),
    )
    if r["code"] != 0:
        raise RuntimeError("x-ui setting failed:\n" + (r["out"] or ""))

    r_tok = await run(xui_exe, ["setting", "-getApiToken"], quiet=True, timeout=30, env=xui_env())
    m = re.search(r"apiToken:\s*(\S+)", r_tok["out"] or "")
    if not m or not m.group(1):
        raise RuntimeError("could not mint 3x-ui API token:\n" + (r_tok["out"] or ""))
    token = m.group(1).strip()
    save_state({"adminUser": user, "adminPass": password, "apiToken": token})
    ok("admin credentials ready (%s)" % user)
    return {"user": user, "password": password, "token": token}


_UNSET = object()


async def api(method, url_path, token=None, json_body=_UNSET, timeout=None):
    headers = {}
    payload = None
    if json_body is not _UNSET:
        headers["Content-Type"] = "application/json"
        payload = jdumps(json_body)
    if token:
        headers["Authorization"] = "Bearer " + token
    r = await request(
        "http://127.0.0.1:%d%s" % (PANEL_PORT, url_path),
        method=method,
        headers=headers,
        body=payload,
        timeout=timeout or 20,
    )
    text = r.body.decode("utf8", errors="replace")
    try:
        parsed = json.loads(text)
    except Exception:
        parsed = text
    return {"status": r.status, "data": parsed}


def reload_panel_in_process():
    if panel_running():
        try:
            CHILD["panel"].send_signal(signal.SIGHUP)
        except Exception:
            pass


def _ok_data(res):
    d = res["data"]
    return isinstance(d, dict) and bool(d.get("success"))


def _obj_list(res):
    d = res["data"]
    if res["status"] == 200 and isinstance(d, dict) and isinstance(d.get("obj"), list):
        return d["obj"]
    return []


async def ensure_panel_and_sub_settings(token, public_host):
    host = public_host or "127.0.0.1"
    r = await api("POST", "/panel/api/setting/all", token=token)
    if r["status"] != 200 or not isinstance(r["data"], dict) or not r["data"].get("success") or not r["data"].get("obj"):
        raise RuntimeError("could not read 3x-ui settings: " + jdumps(r["data"])[:300])
    cur = r["data"]["obj"]
    want_sub_uri = "http://%s:%d/sub/" % (host, PUBLIC_PORT)
    want_json_uri = "http://%s:%d/json/" % (host, PUBLIC_PORT)
    want_clash_uri = "http://%s:%d/clash/" % (host, PUBLIC_PORT)

    sub_changed = (
        cur.get("subEnable") is not True
        or cur.get("subJsonEnable") is not True
        or cur.get("subClashEnable") is not True
        or cur.get("subListen") != "127.0.0.1"
        or cur.get("subPort") != SUB_PORT
        or cur.get("subPath") != "/sub/"
        or cur.get("subJsonPath") != "/json/"
        or cur.get("subClashPath") != "/clash/"
        or cur.get("subURI") != want_sub_uri
        or cur.get("subJsonURI") != want_json_uri
        or cur.get("subClashURI") != want_clash_uri
    )

    if sub_changed:
        nxt = dict(cur)
        nxt.update(
            {
                "webListen": "127.0.0.1",
                "webPort": PANEL_PORT,
                "webBasePath": "/",
                "trustedProxyCIDRs": "127.0.0.1/32,::1/128",
                "subEnable": True,
                "subJsonEnable": True,
                "subClashEnable": True,
                "subListen": "127.0.0.1",
                "subPort": SUB_PORT,
                "subPath": "/sub/",
                "subJsonPath": "/json/",
                "subClashPath": "/clash/",
                "subURI": want_sub_uri,
                "subJsonURI": want_json_uri,
                "subClashURI": want_clash_uri,
            }
        )
        up = await api("POST", "/panel/api/setting/update", token=token, json_body=nxt)
        if up["status"] != 200 or not _ok_data(up):
            warn("could not update sub settings: " + jdumps(up["data"])[:250])
        else:
            reload_panel_in_process()
            await asyncio.sleep(1.2)
            await wait_for_panel(30)
            ok("subscription service configured on 127.0.0.1:%d -> %s" % (SUB_PORT, want_sub_uri))
    else:
        ok("subscription service ready (%s)" % want_sub_uri)

    DYNAMIC_ROUTES["subPaths"] = ["/sub/", "/json/", "/clash/"]
    STATE["subUp"] = await port_open(SUB_PORT, 1.5)


def parse_json_safe(v, fallback=None):
    if fallback is None:
        fallback = {}
    if isinstance(v, (dict, list)):
        return v
    try:
        return json.loads(str(v or ""))
    except Exception:
        return dict(fallback) if isinstance(fallback, dict) else fallback


def get_inbound_transport_path(stream, proto, ib_id):
    stream = stream or {}
    net_type = str(stream.get("network") or "tcp").lower()
    if net_type == "ws":
        ws = stream.get("wsSettings") or {}
        return ws.get("path") or "/"
    if net_type == "httpupgrade":
        hu = stream.get("httpupgradeSettings") or {}
        return hu.get("path") or "/"
    if net_type == "xhttp":
        xh = stream.get("xhttpSettings") or {}
        return xh.get("path") or "/"
    if net_type == "grpc":
        gr = stream.get("grpcSettings") or {}
        svc = gr.get("serviceName") or ""
        return "/" + re.sub(r"^/+", "", svc) if svc else ""
    if net_type == "tcp":
        tcp = stream.get("tcpSettings") or {}
        hdr = tcp.get("header") or {}
        if hdr.get("type") == "http":
            req = hdr.get("request") or {}
            paths = req.get("path")
            if isinstance(paths, list) and paths and paths[0]:
                return paths[0]
    return ""


def set_inbound_transport_path(stream, new_path):
    net_type = str((stream or {}).get("network") or "tcp").lower()
    if net_type == "ws":
        stream["wsSettings"] = {
            **{"acceptProxyProtocol": False, "host": "", "headers": {}},
            **(stream.get("wsSettings") or {}),
            "path": new_path,
        }
    elif net_type == "httpupgrade":
        stream["httpupgradeSettings"] = {
            **{"acceptProxyProtocol": False, "host": "", "headers": {}},
            **(stream.get("httpupgradeSettings") or {}),
            "path": new_path,
        }
    elif net_type == "xhttp":
        stream["xhttpSettings"] = {
            **{"host": "", "mode": "auto"},
            **(stream.get("xhttpSettings") or {}),
            "path": new_path,
        }


async def ensure_default_inbound(token, public_host):
    lst = await api("GET", "/panel/api/inbounds/list", token=token)
    inbounds = _obj_list(lst)
    if len(inbounds) > 0:
        ok("existing inbound(s) found (%d)" % len(inbounds))
        return inbounds

    st = read_state()
    client_uuid = st.get("defaultClientUuid") or uuid4()
    client_sub_id = st.get("defaultClientSubId") or "kb" + random_lower_num(12)
    save_state({"defaultClientUuid": client_uuid, "defaultClientSubId": client_sub_id})

    host = public_host or "127.0.0.1"
    ws_path = TUNNELS[0]["path"] if TUNNELS else "/vless-ws"

    step("creating default inbound (%s on 127.0.0.1:%d)" % (DEFAULT_INBOUND_REMARK, XRAY_PORT))
    body = {
        "up": 0,
        "down": 0,
        "total": 0,
        "remark": DEFAULT_INBOUND_REMARK,
        "enable": True,
        "expiryTime": 0,
        "listen": "127.0.0.1",
        "port": XRAY_PORT,
        "protocol": "vless",
        "shareAddrStrategy": "custom",
        "shareAddr": host,
        "settings": jdumps_pretty(
            {
                "clients": [
                    {
                        "id": client_uuid,
                        "flow": "",
                        "email": DEFAULT_CLIENT_EMAIL,
                        "limitIp": 0,
                        "totalGB": 0,
                        "expiryTime": 0,
                        "enable": True,
                        "tgId": 0,
                        "subId": client_sub_id,
                        "comment": "KataBump ready-to-use config",
                        "reset": 0,
                    }
                ],
                "decryption": "none",
                "encryption": "none",
                "fallbacks": [],
            }
        ),
        "streamSettings": jdumps_pretty(
            {
                "network": "ws",
                "security": "none",
                "externalProxy": [
                    {
                        "forceTls": "same",
                        "dest": host,
                        "port": PUBLIC_PORT,
                        "remark": "",
                    }
                ],
                "wsSettings": {
                    "acceptProxyProtocol": False,
                    "path": ws_path,
                    "host": "",
                    "headers": {},
                },
            }
        ),
        "sniffing": jdumps_pretty(
            {
                "enabled": True,
                "destOverride": ["http", "tls", "quic", "fakedns"],
                "metadataOnly": False,
                "routeOnly": False,
            }
        ),
    }

    add = await api("POST", "/panel/api/inbounds/add", token=token, json_body=body)
    if add["status"] != 200 or not _ok_data(add):
        raise RuntimeError("could not create default inbound: " + jdumps(add["data"])[:400])
    ok("default inbound & client created (%s)" % DEFAULT_CLIENT_EMAIL)

    after = await api("GET", "/panel/api/inbounds/list", token=token)
    return _obj_list(after)


def _encode_uri_component(s):
    return urllib.parse.quote(str(s), safe="-_.!~*'()")


def _num(v):
    try:
        return float(v)
    except Exception:
        return float("nan")


async def sync_inbounds_and_hosts(token, public_host):
    host = public_host or STATE.get("publicHost") or "127.0.0.1"
    want_host_entry = "%s:%d" % (host, PUBLIC_PORT)

    inb_res, host_res = await asyncio.gather(
        api("GET", "/panel/api/inbounds/list", token=token),
        api("GET", "/panel/api/hosts/list", token=token),
    )

    inbounds = _obj_list(inb_res)
    host_groups = _obj_list(host_res)

    path_routes = []
    tls_routes = []
    ws_default_port = 0
    raw_tcp_port = 0
    xray_needs_restart = False

    reserved_prefixes = ["/panel", "/login", "/logout", "/assets", "/sub", "/json", "/clash", "/_kb", "/ws"]
    used_paths = set()

    for ib in inbounds:
        if not ib or ib.get("nodeId") is not None:
            continue
        settings = parse_json_safe(ib.get("settings"), {})
        stream = parse_json_safe(ib.get("streamSettings"), {})
        sniffing = parse_json_safe(
            ib.get("sniffing"), {"enabled": True, "destOverride": ["http", "tls", "quic", "fakedns"]}
        )
        net_type = str(stream.get("network") or "tcp").lower()
        sec_type = str(stream.get("security") or "none").lower()

        tr_path = get_inbound_transport_path(stream, ib.get("protocol"), ib.get("id"))
        stream_modified = False

        # Ensure path-based transports (ws/httpupgrade/xhttp) have a non-conflicting path on the single public port
        if AUTO_HOST_SYNC and net_type in ("ws", "httpupgrade", "xhttp"):
            collides_with_panel = (
                not tr_path
                or tr_path == "/"
                or any(tr_path == p or tr_path.startswith(p + "/") for p in reserved_prefixes)
                or tr_path in used_paths
            )

            if collides_with_panel:
                if ib.get("port") == XRAY_PORT and TUNNELS[0]["path"] not in used_paths:
                    tr_path = TUNNELS[0]["path"]
                else:
                    tr_path = "/%s-%s" % (ib.get("protocol"), ib.get("id"))
                set_inbound_transport_path(stream, tr_path)
                stream_modified = True
            used_paths.add(tr_path)

        # Ensure externalProxy on the inbound always advertises publicHost:PUBLIC_PORT for the Inbounds page UI
        if AUTO_HOST_SYNC:
            eps = stream.get("externalProxy") if isinstance(stream.get("externalProxy"), list) else []
            ep_ok = (
                len(eps) == 1
                and isinstance(eps[0], dict)
                and eps[0].get("dest") == host
                and _num(eps[0].get("port")) == PUBLIC_PORT
            )
            share_ok = ib.get("shareAddrStrategy") == "custom" and ib.get("shareAddr") == host

            if not ep_ok or not share_ok or stream_modified:
                stream["externalProxy"] = [
                    {
                        "forceTls": "same",
                        "dest": host,
                        "port": PUBLIC_PORT,
                        "remark": "",
                    }
                ]
                update_payload = {
                    "up": ib.get("up") or 0,
                    "down": ib.get("down") or 0,
                    "total": ib.get("total") or 0,
                    "remark": ib.get("remark") or "%s-%s" % (ib.get("protocol"), ib.get("id")),
                    "enable": ib.get("enable") is not False,
                    "expiryTime": ib.get("expiryTime") or 0,
                    "TrafficReset": ib.get("trafficReset") or "never",
                    "TrafficResetDay": ib.get("trafficResetDay") or 1,
                    "listen": ib.get("listen") or "127.0.0.1",
                    "port": ib.get("port"),
                    "protocol": ib.get("protocol"),
                    "shareAddrStrategy": "custom",
                    "shareAddr": host,
                    "disableFlow": bool(ib.get("disableFlow")),
                    "settings": jdumps(settings),
                    "streamSettings": jdumps(stream),
                    "sniffing": jdumps(sniffing),
                }
                up_res = await api(
                    "POST",
                    "/panel/api/inbounds/update/%s" % ib.get("id"),
                    token=token,
                    json_body=update_payload,
                )
                if up_res["status"] == 200 and _ok_data(up_res):
                    if stream_modified:
                        xray_needs_restart = True

            # Ensure Hosts table (/panel/api/hosts) has a clean entry pointing to publicHost:PUBLIC_PORT
            existing_host = None
            for g in host_groups:
                if g and isinstance(g.get("inboundIds"), list) and ib.get("id") in g["inboundIds"]:
                    existing_host = g
                    break
            want_remark = "Katabump (%s)" % (ib.get("remark") or ib.get("protocol"))
            if (
                existing_host
                and existing_host.get("remark")
                and not re.match(r"^imported\s+\d+$", existing_host["remark"], re.I)
            ):
                host_remark = existing_host["remark"]
            else:
                host_remark = want_remark
            host_body = {
                "groupId": existing_host.get("groupId") if existing_host else "kbhost_%s" % ib.get("id"),
                "inboundIds": existing_host.get("inboundIds") if existing_host else [ib.get("id")],
                "hosts": [want_host_entry],
                "sortOrder": (existing_host.get("sortOrder") or 0) if existing_host else 0,
                "remark": host_remark,
                "serverDescription": "",
                "isDisabled": False,
                "isHidden": False,
                "port": PUBLIC_PORT,
                "security": "same",
                "path": tr_path or "",
            }

            if not existing_host:
                await api("POST", "/panel/api/hosts/add", token=token, json_body=host_body)
            else:
                hosts_list = existing_host.get("hosts")
                same_addr = (
                    isinstance(hosts_list, list)
                    and len(hosts_list) == 1
                    and hosts_list[0] == want_host_entry
                    and existing_host.get("port") == PUBLIC_PORT
                    and not existing_host.get("isDisabled")
                    and not existing_host.get("serverDescription")
                    and not re.match(r"^imported\s+\d+$", existing_host.get("remark") or "", re.I)
                    and (existing_host.get("path") or "") == (tr_path or "")
                )
                if not same_addr:
                    await api(
                        "POST",
                        "/panel/api/hosts/update/%s" % _encode_uri_component(existing_host.get("groupId")),
                        token=token,
                        json_body=host_body,
                    )

        if ib.get("enable") is not False:
            if tr_path and tr_path != "/":
                path_routes.append(
                    {
                        "path": tr_path,
                        "port": ib.get("port"),
                        "proto": ib.get("protocol"),
                        "remark": ib.get("remark"),
                        "network": net_type,
                    }
                )
            if net_type == "ws" and not ws_default_port:
                ws_default_port = ib.get("port")
            if sec_type in ("reality", "tls"):
                sni = ""
                if (
                    sec_type == "reality"
                    and isinstance(stream.get("realitySettings"), dict)
                    and isinstance(stream["realitySettings"].get("serverNames"), list)
                ):
                    names = stream["realitySettings"]["serverNames"]
                    sni = (names[0] if names else "") or ""
                elif sec_type == "tls" and stream.get("tlsSettings"):
                    sni = stream["tlsSettings"].get("serverName") or ""
                tls_routes.append(
                    {
                        "sni": sni.lower(),
                        "port": ib.get("port"),
                        "proto": ib.get("protocol"),
                        "remark": ib.get("remark"),
                    }
                )
            elif net_type == "tcp" and not tr_path and not raw_tcp_port:
                raw_tcp_port = ib.get("port")

    if xray_needs_restart:
        await api("POST", "/panel/api/server/restartXrayService", token=token)

    DYNAMIC_ROUTES["pathRoutes"] = path_routes
    DYNAMIC_ROUTES["wsDefaultPort"] = ws_default_port or XRAY_PORT
    DYNAMIC_ROUTES["tlsRoutes"] = tls_routes
    DYNAMIC_ROUTES["rawTcpPort"] = raw_tcp_port

    summary = []
    for ib in inbounds:
        stream = parse_json_safe(ib.get("streamSettings"), {})
        summary.append(
            {
                "id": ib.get("id"),
                "remark": ib.get("remark"),
                "protocol": ib.get("protocol"),
                "network": stream.get("network") or "tcp",
                "port": ib.get("port"),
                "path": get_inbound_transport_path(stream, ib.get("protocol"), ib.get("id")) or "-",
                "enable": ib.get("enable") is not False,
            }
        )
    STATE["inbounds"] = summary

    # Refresh ready-to-use links for state & PANEL.txt
    try:
        all_links = await api("GET", "/panel/api/inbounds/allLinks", token=token)
        links = _obj_list(all_links)
        if links:
            STATE["shareLink"] = links[0]
    except Exception:
        pass

    try:
        for ib in inbounds:
            settings = parse_json_safe(ib.get("settings"), {})
            clients = settings.get("clients") if isinstance(settings.get("clients"), list) else []
            first_sub = next((c for c in clients if c and c.get("subId")), None)
            if first_sub and first_sub.get("subId"):
                STATE["subUrl"] = "http://%s:%d/sub/%s" % (host, PUBLIC_PORT, first_sub["subId"])
                STATE["subJsonUrl"] = "http://%s:%d/json/%s" % (host, PUBLIC_PORT, first_sub["subId"])
                break
    except Exception:
        pass


# --------------------------- public port -------------------------- #

_STATUS_TEMPLATE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>3x-ui on KataBump</title>
<style>body{margin:0;background:#0b1020;color:#e6e9f2;font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif}
.wrap{max-width:780px;margin:0 auto;padding:32px 20px}
h1{font-size:22px;margin:0 0 4px}.sub{color:#8b93ad;margin-bottom:24px}
.card{background:#111832;border:1px solid #1f2a44;border-radius:14px;padding:20px;margin-bottom:16px}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:@@COLOR@@;margin-right:8px}
table{width:100%;border-collapse:collapse;margin-top:8px}td,th{padding:6px 8px;border-bottom:1px solid #1f2a44;text-align:left;font-size:14px}
code{background:#0b1020;padding:2px 6px;border-radius:6px;font-size:13px}
a{color:#7dd3fc}</style></head><body><div class="wrap">
<h1><span class="dot"></span>3x-ui (Sanaei) on KataBump</h1>
<div class="sub">@@WRAPPER@@ — panel @@XUI@@ · @@XRAY@@</div>
<div class="card"><b>Status:</b> @@STEP@@ @@ERROR@@<br>
<b>Public port:</b> @@PUBPORT@@ · <b>Panel:</b> 127.0.0.1:@@PANELPORT@@ (@@PANELUP@@) · <b>Sub:</b> 127.0.0.1:@@SUBPORT@@ (@@SUBUP@@) · <b>Core:</b> @@COREUP@@<br>
<b>Public host:</b> @@HOST@@</div>
<div class="card"><b>Links</b><br>
<a href="/panel/">/panel/</a> — 3x-ui web panel<br>
<a href="/panel/inbounds">/panel/inbounds</a> — Inbounds · <a href="/panel/hosts">/panel/hosts</a> — Hosts<br>
<a href="@@STATUSPATH@@">@@STATUSPATH@@</a> — KataBump wrapper status</div>
@@SHARE@@
<div class="card"><b>Multiplexed Tunnels on Public Port @@PUBPORT@@</b>
<table><tr><th>proto</th><th>path</th><th>local port</th><th>remark</th></tr>@@ROWS@@</table></div>
</div></body></html>"""


def _esc(x):
    s = "" if x is None else str(x)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def status_html():
    s = STATE
    all_tunnels = []
    seen = set()
    for t in s.get("tunnels") or []:
        k = "%s:%s" % (t["path"], t["port"])
        if k not in seen:
            seen.add(k)
            all_tunnels.append(
                {"proto": t["proto"], "path": t["path"], "port": t["port"], "note": "static tunnel"}
            )
    for r in DYNAMIC_ROUTES["pathRoutes"] or []:
        k = "%s:%s" % (r["path"], r["port"])
        if k not in seen:
            seen.add(k)
            all_tunnels.append(
                {
                    "proto": r["proto"],
                    "path": r["path"],
                    "port": r["port"],
                    "note": r.get("remark") or r.get("network"),
                }
            )
    rows = "".join(
        "<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>"
        % (_esc(t["proto"]), _esc(t["path"]), t["port"], _esc(t.get("note") or ""))
        for t in all_tunnels
    )
    color = "#ff6b6b" if s.get("error") else ("#4ade80" if s.get("panelUp") else "#fbbf24")
    if s.get("shareLink"):
        sub_part = ""
        if s.get("subUrl"):
            sub_part = (
                '<div style="margin-top:8px"><b>Subscription URL:</b> <a href="%s">%s</a></div>'
                % (_esc(s["subUrl"]), _esc(s["subUrl"]))
            )
        share_section = (
            '<div class="card"><b>Ready-to-Use Config &amp; Subscription</b><br>\n'
            '<div style="margin-top:8px"><b>Share Link:</b><br>'
            '<code style="word-break:break-all;display:block;padding:8px;margin-top:4px">%s</code></div>\n'
            "%s\n</div>" % (_esc(s["shareLink"]), sub_part)
        )
    else:
        share_section = ""

    vals = {
        "COLOR": color,
        "WRAPPER": _esc(WRAPPER),
        "XUI": _esc(s.get("xui") or "?"),
        "XRAY": _esc(s.get("xray") or "xray-core"),
        "STEP": _esc(s.get("step")),
        "ERROR": ("— " + _esc(s["error"])) if s.get("error") else "",
        "PUBPORT": str(s.get("publicPort")),
        "PANELPORT": str(s.get("panelPort")),
        "PANELUP": "up" if s.get("panelUp") else "down",
        "SUBPORT": str(s.get("subPort")),
        "SUBUP": "up" if s.get("subUp") else "down",
        "COREUP": "up" if s.get("coreUp") else "down",
        "HOST": _esc(s.get("publicHost") or "detecting…"),
        "STATUSPATH": STATUS_PATH,
        "SHARE": share_section,
        "ROWS": rows,
    }
    return re.sub(r"@@(\w+)@@", lambda m: vals[m.group(1)], _STATUS_TEMPLATE)


async def write_response(writer, status, body, ctype, extra_headers=None):
    b = body.encode("utf8")
    head = "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nCache-Control: no-store\r\n" % (
        status,
        ctype,
        len(b),
    )
    if extra_headers:
        for k, v in extra_headers.items():
            head += "%s: %s\r\n" % (k, v)
    head += "Connection: close\r\n\r\n"
    try:
        writer.write(head.encode("latin1") + b)
        await writer.drain()
    except Exception:
        pass
    _close_writer(writer)


def _close_writer(w):
    try:
        w.close()
    except Exception:
        pass


def with_forwarded(buf, ip):
    s = buf.decode("latin1")
    idx = s.find("\r\n")
    if idx < 0:
        return buf
    host_match = re.search(r"\r\nHost:\s*([^\r\n]*)", s, re.I)
    clean_ip = re.sub(r"^::ffff:", "", str(ip or "127.0.0.1"))
    extra = "X-Forwarded-For: %s\r\nX-Forwarded-Proto: http\r\n" % clean_ip
    if host_match:
        extra += "X-Forwarded-Host: %s\r\n" % host_match.group(1).strip()
    return (s[: idx + 2] + extra + s[idx + 2 :]).encode("latin1")


HTTP_METHODS_RE = re.compile(r"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE|PRI)\s+")


def parse_tls_sni(buf):
    try:
        if len(buf) < 43 or buf[0] != 0x16 or buf[1] != 0x03:
            return ""
        if buf[5] != 0x01:  # ClientHello
            return ""
        pos = 43
        if pos >= len(buf):
            return ""
        sess_id_len = buf[pos]
        pos += 1 + sess_id_len
        if pos + 2 > len(buf):
            return ""
        cipher_len = int.from_bytes(buf[pos : pos + 2], "big")
        pos += 2 + cipher_len
        if pos + 1 > len(buf):
            return ""
        comp_len = buf[pos]
        pos += 1 + comp_len
        if pos + 2 > len(buf):
            return ""
        ext_total_len = int.from_bytes(buf[pos : pos + 2], "big")
        pos += 2
        end = min(len(buf), pos + ext_total_len)
        while pos + 4 <= end:
            ext_type = int.from_bytes(buf[pos : pos + 2], "big")
            ext_len = int.from_bytes(buf[pos + 2 : pos + 4], "big")
            pos += 4
            if ext_type == 0x0000 and pos + 5 <= end:
                name_len = int.from_bytes(buf[pos + 3 : pos + 5], "big")
                if pos + 5 + name_len <= end:
                    return buf[pos + 5 : pos + 5 + name_len].decode("ascii", errors="replace").lower()
            pos += ext_len
    except Exception:
        pass
    return ""


async def _pump(src, dst, sniff_panel=False):
    """Copy src -> dst. Returns True on clean EOF, False on error."""
    try:
        while True:
            chunk = await src.read(65536)
            if not chunk:
                break
            if sniff_panel:
                s = chunk[:512].decode("latin1")
                if "/panel/api/inbounds/" in s or "/panel/api/clients/" in s:
                    schedule_quick_sync()
            dst.write(chunk)
            await dst.drain()
    except Exception:
        return False
    try:
        if dst.can_write_eof():
            dst.write_eof()
    except Exception:
        pass
    return True


async def pipe_to_local_port(creader, cwriter, port, buf, add_forwarded, ip):
    try:
        ureader, uwriter = await asyncio.open_connection("127.0.0.1", port)
    except Exception:
        try:
            cwriter.write(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 21\r\nConnection: close\r\n\r\nupstream unavailable\n"
            )
            await cwriter.drain()
        except Exception:
            pass
        _close_writer(cwriter)
        return
    try:
        uwriter.write(with_forwarded(buf, ip) if add_forwarded else buf)
        await uwriter.drain()
    except Exception:
        _close_writer(uwriter)
        _close_writer(cwriter)
        return

    t1 = asyncio.ensure_future(_pump(creader, uwriter, port == PANEL_PORT))
    t2 = asyncio.ensure_future(_pump(ureader, cwriter))
    try:
        pending = {t1, t2}
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            # upstream finished (or any side failed) -> nothing more can be delivered, close both.
            # client finished cleanly -> keep waiting so the upstream can still answer.
            if t2 in done or any((d.exception() is not None) or (d.result() is False) for d in done):
                break
    except Exception:
        pass
    finally:
        for t in (t1, t2):
            if not t.done():
                t.cancel()
        _close_writer(uwriter)
        _close_writer(cwriter)


async def route(creader, cwriter, buf, ip):
    # 1. Check TLS / REALITY ClientHello (0x16 0x03)
    if len(buf) >= 3 and buf[0] == 0x16 and buf[1] == 0x03:
        if len(DYNAMIC_ROUTES["tlsRoutes"]) > 0:
            sni = parse_tls_sni(buf)
            matched = None
            if sni:
                matched = next((r for r in DYNAMIC_ROUTES["tlsRoutes"] if r["sni"] == sni), None)
            if not matched:
                matched = DYNAMIC_ROUTES["tlsRoutes"][0]
            return await pipe_to_local_port(creader, cwriter, matched["port"], buf, False, ip)

    head = buf[:4096].decode("latin1")

    # 2. Check non-HTTP binary TCP protocol (e.g. raw VLESS / VMess / Shadowsocks TCP)
    if not HTTP_METHODS_RE.match(head):
        raw_port = DYNAMIC_ROUTES["rawTcpPort"] or XRAY_PORT
        return await pipe_to_local_port(creader, cwriter, raw_port, buf, False, ip)

    line = head.split("\r\n")[0] or ""
    parts = line.split(" ")
    url_path = parts[1] if len(parts) > 1 else None
    clean = (url_path or "/").split("?")[0]

    # 3. Wrapper status endpoint
    if clean == STATUS_PATH:
        body = jdumps_pretty(STATE)
        is_html = bool(re.search(r"text/html", head, re.I))
        return await write_response(
            cwriter,
            200,
            status_html() if is_html else body,
            "text/html; charset=utf-8" if is_html else "application/json",
        )

    # 4. Static & dynamic Xray tunnel paths (WS, HTTPUpgrade, XHTTP/SplitHTTP, gRPC, TCP-HTTP)
    static_tun = next((t for t in TUNNELS if clean == t["path"] or clean.startswith(t["path"] + "/")), None)
    if static_tun:
        return await pipe_to_local_port(creader, cwriter, static_tun["port"], buf, False, ip)
    dyn_tun = next(
        (r for r in DYNAMIC_ROUTES["pathRoutes"] if clean == r["path"] or clean.startswith(r["path"] + "/")),
        None,
    )
    if dyn_tun:
        return await pipe_to_local_port(creader, cwriter, dyn_tun["port"], buf, False, ip)

    # 5. Non-panel WebSocket Upgrade fallback (e.g. WS inbound with path "/")
    if re.search(r"\r\nUpgrade:\s*websocket", head, re.I) and clean != "/ws" and not clean.endswith("/ws"):
        ws_port = DYNAMIC_ROUTES["wsDefaultPort"] or XRAY_PORT
        return await pipe_to_local_port(creader, cwriter, ws_port, buf, False, ip)

    # 6. Subscription service paths (/sub/..., /json/..., /clash/...)
    is_sub_path = any(
        clean == re.sub(r"/$", "", sp, count=1) or clean.startswith(sp) for sp in DYNAMIC_ROUTES["subPaths"]
    )
    if is_sub_path:
        return await pipe_to_local_port(creader, cwriter, SUB_PORT, buf, True, ip)

    # 7. 3x-ui Web Panel
    if not STATE["panelUp"]:
        return await write_response(
            cwriter,
            503,
            status_html().replace("<title>3x-ui on KataBump</title>", "<title>3x-ui — starting</title>"),
            "text/html; charset=utf-8",
        )

    if re.match(r"^POST\s+", line, re.I) and (
        clean.startswith("/panel/api/inbounds/") or clean.startswith("/panel/api/clients/")
    ):
        schedule_quick_sync()

    return await pipe_to_local_port(creader, cwriter, PANEL_PORT, buf, True, ip)


async def handle_client(reader, writer):
    try:
        sock = writer.get_extra_info("socket")
        if sock is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "127.0.0.1"
        try:
            first = await reader.read(65536)
        except Exception:
            _close_writer(writer)
            return
        if not first:
            _close_writer(writer)
            return
        await route(reader, writer, first, ip)
    except Exception:
        _close_writer(writer)


async def start_proxy():
    try:
        server = await asyncio.start_server(handle_client, "0.0.0.0", PUBLIC_PORT)
    except OSError as e:
        err("public port error: " + str(e))
        STATE["error"] = str(e)
        raise
    return server


# ---------------------------- watchdog ---------------------------- #

_last_sync_at = 0.0
_quick_sync_handle = None
_runtime_ctx = None


def schedule_quick_sync():
    global _quick_sync_handle
    if not _runtime_ctx or not _runtime_ctx.get("token"):
        return
    loop = asyncio.get_running_loop()
    if _quick_sync_handle is not None:
        _quick_sync_handle.cancel()

    async def job():
        global _quick_sync_handle, _last_sync_at
        _quick_sync_handle = None
        try:
            await sync_inbounds_and_hosts(_runtime_ctx["token"], STATE["publicHost"])
            write_cred_file(_runtime_ctx["user"], _runtime_ctx["password"], STATE["publicHost"])
            _last_sync_at = time.time()
        except Exception:
            pass

    _quick_sync_handle = loop.call_later(0.9, lambda: asyncio.ensure_future(job()))


async def watchdog(xui_exe, ctx):
    global _runtime_ctx, _last_sync_at
    _runtime_ctx = ctx
    release_memory()
    while True:
        await asyncio.sleep(15)
        try:
            up = await port_open(PANEL_PORT, 1.5)
            panel_rss = rss_of(CHILD["panel"].pid) if CHILD["panel"] else 0
            STATE["panelRss"] = int(round(panel_rss))

            if up and panel_rss > PANEL_MEM_MAX:
                warn("3x-ui is using %d MB (ceiling %d MB) — restarting" % (round(panel_rss), PANEL_MEM_MAX))
                up = False

            if not up or not CHILD["panel"] or panel_exited():
                warn("3x-ui panel is down — restarting")
                if panel_running():
                    try:
                        CHILD["panel"].terminate()
                    except Exception:
                        pass
                    await asyncio.sleep(1.5)
                    try:
                        CHILD["panel"].kill()
                    except Exception:
                        pass
                STATE["panelUp"] = False
                start_panel_process(xui_exe)
                await wait_for_panel(90)
                STATE["panelUp"] = True
                ok("3x-ui panel is back")
            else:
                STATE["panelUp"] = True

            STATE["subUp"] = await port_open(SUB_PORT, 1.2)
            if not SKIP_XRAY:
                STATE["coreUp"] = await port_open(XRAY_PORT, 1.2)

            # Periodically sync any new inbounds/clients/hosts created by the user in the UI
            if ctx.get("token") and time.time() - _last_sync_at > 15:
                _last_sync_at = time.time()
                try:
                    await sync_inbounds_and_hosts(ctx["token"], STATE["publicHost"])
                    write_cred_file(ctx["user"], ctx["password"], STATE["publicHost"])
                except Exception:
                    pass

            release_memory()
        except Exception as e:
            log("watchdog: " + str(e))


# ----------------------------- banner ----------------------------- #


def write_cred_file(user, password, public_host):
    host = public_host or "YOUR-SERVER-IP"
    lines = [
        "3x-ui (MHSanaei) on KataBump",
        "============================",
        "",
        "Panel URL        : http://%s:%d/panel/" % (host, PUBLIC_PORT),
        "Hosts Manager    : http://%s:%d/panel/hosts" % (host, PUBLIC_PORT),
        "Wrapper Status   : http://%s:%d%s" % (host, PUBLIC_PORT, STATUS_PATH),
        "",
        "Username         : %s" % user,
        "Password         : %s" % password,
        "",
        "3x-ui Version    : %s" % (STATE.get("xui") or "unknown"),
        "Xray Core        : %s" % (STATE.get("xray") or "unknown"),
        "Default Inbound  : %s -> 127.0.0.1:%d (ws path %s)"
        % (DEFAULT_INBOUND_REMARK, XRAY_PORT, TUNNELS[0]["path"]),
        "External Host    : %s:%d" % (host, PUBLIC_PORT),
        "",
    ]
    if STATE.get("subUrl"):
        lines.append("Subscription URL : %s" % STATE["subUrl"])
    if STATE.get("subJsonUrl"):
        lines.append("JSON Sub URL     : %s" % STATE["subJsonUrl"])
    if STATE.get("shareLink"):
        lines.extend(["", "Ready-to-Use VLESS Config:", STATE["shareLink"]])
    lines.extend(["", "Data (persistent): " + DATA, "Logs             : " + LOGS, ""])
    try:
        with open(CRED_FILE, "w", encoding="utf8") as f:
            f.write("\n".join(lines))
    except Exception:
        pass
    return "\n".join(lines)


def banner(user, password, public_host):
    host = public_host or "YOUR-SERVER-IP"
    line = "─" * 66
    _out("")
    _out(paint("35", "  " + line))
    _out(paint("35", "   3x-ui (MHSanaei) is ready on KataBump"))
    _out(paint("35", "  " + line))
    _out("   panel       http://%s:%d/panel/" % (host, PUBLIC_PORT))
    _out("   status      http://%s:%d%s" % (host, PUBLIC_PORT, STATUS_PATH))
    if STATE.get("subUrl"):
        _out("   sub url     %s" % STATE["subUrl"])
    _out("")
    _out("   username    %s" % user)
    _out("   password    %s" % password)
    if STATE.get("shareLink"):
        _out("")
        _out("   vless link  %s" % STATE["shareLink"])
    _out("")
    _out("   3x-ui %s · %s" % (STATE.get("xui") or "?", STATE.get("xray") or "xray"))
    _out("   data  %s" % DATA)
    _out(paint("35", "  " + line))
    _out("")


# ---------------------------- selftest ---------------------------- #


def self_test():
    log("selftest: checking structure only (no network)")

    def _arch_ok():
        a = arch_asset()
        return bool(a["tar"] and a["xray"])

    def _pw_ok():
        p = strong_password("Katabump123")
        return (
            len(p) >= 12
            and re.search(r"[A-Z].*[A-Z]", p) is not None
            and re.search(r"[0-9].*[0-9]", p) is not None
            and re.search(r"[!@#$%^&*_\-]", p) is not None
        )

    checks = [
        ("wrapper constants", isinstance(WRAPPER, str) and isinstance(PUBLIC_PORT, int)),
        ("tunnels parsed", isinstance(TUNNELS, list) and len(TUNNELS) >= 2),
        ("tar extractor", callable(_extract_tar_gz_sync) and callable(extract_tar_gz)),
        ("arch asset resolver", _arch_ok()),
        ("password policy", _pw_ok()),
        ("status page html", "3x-ui (Sanaei) on KataBump" in status_html()),
    ]
    bad = 0
    for name, passed in checks:
        _out("   %s %s" % (paint("32", "✓") if passed else paint("31", "✗"), name))
        if not passed:
            bad += 1
    _out("   %s" % (paint("31", "%d failed" % bad) if bad else paint("32", "all good")))
    sys.exit(1 if bad else 0)


# ------------------------------ main ------------------------------ #

_SERVER = None
_WATCHDOG_TASK = None


async def bootstrap():
    global _SERVER, _WATCHDOG_TASK, _last_sync_at
    ensure_dirs()
    kill_orphans()

    step("opening public port %d" % PUBLIC_PORT)
    _SERVER = await start_proxy()
    ok("public port %d open" % PUBLIC_PORT)
    release_memory()

    inst = await install_xui(FORCE_SETUP)
    xui_exe = inst["xuiExe"]
    release_memory()

    creds = await configure_cli_settings(xui_exe)
    release_memory()

    step("starting 3x-ui panel")
    start_panel_process(xui_exe)
    await wait_for_panel()
    STATE["panelUp"] = True
    ok("3x-ui panel listening on 127.0.0.1:%d" % PANEL_PORT)
    release_memory()

    public_host = await detect_public_ip()
    STATE["publicHost"] = public_host
    ok("public host detected: %s" % (public_host or "127.0.0.1"))

    step("provisioning subscription service, default inbound & hosts")
    await ensure_panel_and_sub_settings(creds["token"], public_host)
    await ensure_default_inbound(creds["token"], public_host)
    await sync_inbounds_and_hosts(creds["token"], public_host)
    release_memory()

    if not SKIP_XRAY:
        step("waiting for xray inbound to start")
        core_up = False
        for _ in range(25):
            core_up = await port_open(XRAY_PORT, 1.2)
            if core_up:
                break
            await asyncio.sleep(1)
        STATE["coreUp"] = core_up
        if core_up:
            ok("xray inbound listening on 127.0.0.1:%d" % XRAY_PORT)
        else:
            warn("xray inbound is not listening yet — check " + os.path.join(LOGS, "panel.log"))

    STATE["step"] = "ready"
    STATE["admin"] = creds["user"]
    save_state({"adminUser": creds["user"], "adminPass": creds["password"], "publicHost": public_host})

    write_cred_file(creds["user"], creds["password"], public_host)
    banner(creds["user"], creds["password"], public_host)
    release_memory()

    _last_sync_at = time.time()
    _WATCHDOG_TASK = asyncio.ensure_future(watchdog(xui_exe, creds))


def shutdown(sig_name):
    log("shutting down (%s)" % sig_name)
    if panel_running():
        try:
            CHILD["panel"].terminate()
        except Exception:
            pass
    asyncio.get_running_loop().call_later(1.5, lambda: os._exit(0))


async def main():
    global PANEL_PORT, SUB_PORT, XRAY_PORT
    _out("")
    _out(paint("35", "  3x-ui-katabump ") + paint("90", WRAPPER))
    _out(paint("90", "  MHSanaei 3x-ui %s · single public port %d" % (XUI_VERSION, PUBLIC_PORT)))
    _out("")
    if ENV.get("SELFTEST") == "1":
        return self_test()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda s=sig: shutdown(s.name))
        except Exception:
            pass

    used = {PUBLIC_PORT}

    async def pick(preferred, fallback_start):
        if preferred not in used and not (await port_open(preferred, 0.4)):
            used.add(preferred)
            return preferred
        p = first_free_port([fallback_start, fallback_start + 1, fallback_start + 2, fallback_start + 3])
        used.add(p)
        return p

    PANEL_PORT = await pick(PANEL_PORT, 18080)
    SUB_PORT = await pick(SUB_PORT, 18096)
    XRAY_PORT = await pick(XRAY_PORT, 21001)
    for t in TUNNELS:
        if t["port"] == 21001:
            t["port"] = XRAY_PORT
    STATE["panelPort"] = PANEL_PORT
    STATE["subPort"] = SUB_PORT

    try:
        await bootstrap()
    except Exception as e:
        import traceback

        STATE["error"] = str(e)
        STATE["step"] = "error"
        err(str(e))
        traceback.print_exc()
        while True:
            await asyncio.sleep(60)

    # keep the process alive (public port server + watchdog run on this loop)
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
