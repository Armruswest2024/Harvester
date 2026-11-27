#!/usr/bin/env python3
"""
Harvester Lite v2 — быстрый агрегатор и валидатор прокси.
Двухфазное тестирование:
  Фаза 1: быстрый TCP-ping для ВСЕХ нод (~0.3с/ноду)
  Фаза 2: xray + speedtest только для прошедших фазу 1

Запуск:   python harvester.py
Выход:    assets/ping_tested.txt  assets/speed_tested.txt  assets/non_ru.txt
"""

import asyncio
import base64
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import aiohttp

# ═══════════════════════════════════════════════════════════════
SCRIPT_DIR = Path(__file__).parent.resolve()
NODES_FILE = SCRIPT_DIR / "core" / "nodes.txt"
ASSETS_DIR = SCRIPT_DIR / "assets"
BIN_DIR = SCRIPT_DIR / "bin"
XRAY_EXE   = BIN_DIR / "xray.exe" if os.name == "nt" else BIN_DIR / "xray"

PING_OUT      = ASSETS_DIR / "ping_tested.txt"
SPEED_OUT     = ASSETS_DIR / "speed_tested.txt"
NON_RU_OUT    = ASSETS_DIR / "non_ru.txt"

TCP_TIMEOUT   = 3.0          # фаза 1 — таймаут подключения
IP_TIMEOUT    = 5            # фаза 2 — получение IP через прокси
SPEED_TIMEOUT = 10           # фаза 2 — общий таймаут speedtest
MIN_SPEED     = 10           # мин. скорость Мбит/с для прохождения

MAX_WORKERS = 100            # параллельных TCP-подключений (фаза 1)
MAX_XRAY    = 60             # parallel xray tests (phase 2)
PORT_BASE   = 28_000

# ═══════════════════════════════════════════════════════════════
VLESS_RE  = re.compile(r"^vless://",  re.I)
VMESS_RE  = re.compile(r"^vmess://", re.I)
TROJAN_RE = re.compile(r"^trojan://",re.I)
SS_RE     = re.compile(r"^ss://",    re.I)
IP_RE     = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


# ═══════════════════════════════════════════════════════════════
# Лёгкий SOCKS5-клиент без внешних зависимостей
# ═══════════════════════════════════════════════════════════════
async def _socks5_connect(proxy_host, proxy_port, dest_host, dest_port, timeout=10):
    """Открывает SOCKS5-туннель до dest и возвращает (reader, writer)."""
    import struct

    async def _read_exact(n, src):
        data = b""
        while len(data) < n:
            chunk = await asyncio.wait_for(src.read(n - len(data)), timeout=timeout)
            if not chunk: raise EOFError("socket closed")
            data += chunk
        return data

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port), timeout=timeout)
    except Exception as e:
        raise RuntimeError(f"connect failed: {e}")

    try:
        # Handshake: version=5, methods=[NOAUTH]
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        resp = await _read_exact(2, reader)
        if resp[0] != 0x05 or resp[1] != 0x00:
            writer.close(); await writer.wait_closed()
            raise RuntimeError(f"handshake failed: {resp.hex()}")

        # CONNECT request: VER(05) CMD(01) RSV(00) ATYP(atyp) ADDR(addr) PORT(port)
        is_ip = bool(IP_RE.match(dest_host))
        if is_ip:
            addr_type = b"\x01"
            addr = bytes(int(x) for x in dest_host.split("."))
        else:
            addr_type = b"\x03"
            addr = len(dest_host).to_bytes(1, "big") + dest_host.encode()
        port_b = struct.pack(">H", dest_port)
        
        # RSV = \x00
        writer.write(b"\x05\x01\x00" + addr_type + addr + port_b)
        await writer.drain()
        rsep = await _read_exact(4, reader)
        if rsep[0] != 0x05 or rsep[1] != 0x00:
            writer.close(); await writer.wait_closed()
            raise RuntimeError(f"connect failed rep={rsep.hex()}")

        # Skip bound address
        if rsep[2] == 0x01:  # IPv4
            await _read_exact(6, reader)
        elif rsep[2] == 0x03:  # domain
            n = await _read_exact(1, reader)
            await _read_exact(n[0] + 2, reader)
        elif rsep[2] == 0x04:  # IPv6
            await _read_exact(18, reader)
        return reader, writer
    except Exception:
        try: writer.close(); await writer.wait_closed()
        except Exception: pass
        raise



class Node:
    def __init__(self, raw: str):
        self.raw = raw.strip()
        self.protocol = ""
        self.host = ""
        self.port = 0
        self.uuid = ""
        self.password = ""
        self.params: dict = {}
        self.comment = ""
        self._parse()

    def _parse(self):
        if VLESS_RE.match(self.raw):   self._vless()
        elif VMESS_RE.match(self.raw): self._vmess()
        elif TROJAN_RE.match(self.raw):self._trojan()
        elif SS_RE.match(self.raw):    self._ss()

    def _vless(self):
        u = urlparse(self.raw)
        self.uuid = u.username or ""
        self.host = u.hostname or ""
        self.port = u.port or 443
        self.params = parse_qs(u.query)
        self.comment = unquote(u.fragment or "")
        self.protocol = "vless"

    def _vmess(self):
        try:
            o = json.loads(base64.b64decode(self.raw[8:]).decode())
        except Exception:
            return
        self.protocol = "vmess"
        self.host  = o.get("add", "")
        self.port  = int(o.get("port", 0))
        self.uuid  = o.get("id", "")
        self.comment = o.get("ps", "")
        self.params = {
            "type":     [o.get("net",   "tcp")],
            "security": [o.get("tls",   "none")],
            "sec":      [o.get("scy",   "auto")],
            "sni":      [o.get("sni",   "")],
            "fp":       [o.get("fp",    "")],
            "path":     [o.get("path",  "/")],
            "host":     [o.get("host",  "")],
        }

    def _trojan(self):
        u = urlparse(self.raw)
        self.password = u.username or ""
        self.host = u.hostname or ""
        self.port = u.port or 443
        self.comment = unquote(u.fragment or "")
        self.params = parse_qs(u.query)
        self.protocol = "trojan"

    def _ss(self):
        rest = self.raw[5:]
        comment = ""
        if "#" in rest:
            rest, comment = rest.split("#", 1)
            comment = unquote(comment)
        try:
            decoded = base64.b64decode(rest).decode()
        except Exception:
            return
        self.comment = comment
        if "@" in decoded:
            creds, hp = decoded.split("@", 1)
            method, pw = creds.split(":",1) if ":" in creds else (creds,"")
            h, p = hp.rsplit(":",1)
            try:
                self.host, self.port = h, int(p)
                self.params = {"method":[method],"password":[pw]}
                self.protocol = "ss"
            except ValueError:
                pass

    @property
    def usable(self):
        return bool(self.host and self.port and self.host not in ("", "None"))


# ═══════════════════════════════════════════════════════════════
async def fetch_lines(session, url: str) -> list[str]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status != 200: return []
            return [l.strip() for l in (await r.text(errors="replace")).splitlines() if l.strip()]
    except Exception:
        return []


async def collect_nodes(path: Path) -> list[Node]:
    if not path.exists():
        print(f"[!] {path} not found"); sys.exit(1)
    urls = [l.strip() for l in path.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.startswith("#")]
    print(f"[i] Sources: {len(urls)}")
    seen = set(); stats = []
    async with aiohttp.ClientSession() as sess:
        results = await asyncio.gather(*[fetch_lines(sess, u) for u in urls])
    for url, lines in zip(urls, results):
        new = [l for l in lines if l not in seen]
        seen.update(new); stats.append((url[:55], len(lines), len(new)))
    print(f"[i] Unique lines: {len(seen)}")
    for src, tot, uniq in stats: print(f"    {src} ... {tot} total, {uniq} new")
    nodes = []
    bad = 0
    for l in seen:
        try:
            n = Node(l)
            if n.usable: nodes.append(n)
        except Exception:
            bad += 1
    print(f"[i] Valid nodes: {len(nodes)}")
    if bad: print(f"[*] Skipped {bad} unparseable lines")
    return nodes


# ═══════════════════════════════════════════════════════════════
# ФАЗА 1 — чистый TCP-ping, без xray
# ═══════════════════════════════════════════════════════════════
async def tcp_phase(nodes: list[Node]) -> list[Node]:
    sem = asyncio.Semaphore(MAX_WORKERS)
    alive = []

    async def probe(n: Node):
        async with sem:
            try:
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(n.host, n.port), timeout=TCP_TIMEOUT)
                w.close()
                await asyncio.sleep(0.02)
                return n
            except Exception:
                return None

    done = 0
    tasks = [asyncio.create_task(probe(n)) for n in nodes]
    for coro in asyncio.as_completed(tasks):
        r = await coro
        if r: alive.append(r)
        done += 1
        if done % 500 == 0 or done == len(nodes):
            print(f"  [phase1] {done}/{len(nodes)} checked, {len(alive)} alive")
    print(f"[i] Phase 1 done: {len(alive)}/{len(nodes)} survived TCP\n")
    return alive


# ═══════════════════════════════════════════════════════════════
# Генерация конфига xray
# ═══════════════════════════════════════════════════════════════
def build_vless_cfg(node, port):
    p = node.params
    sec  = p.get("security", ["none"])[0].lower()
    net  = p.get("type", ["tcp"])[0].lower()
    sni  = p.get("sni", [node.host])[0]
    fp   = p.get("fp", ["chrome"])[0]
    usr  = {"id": node.uuid, "encryption": "none"}
    if sec in ("reality","tls") and p.get("flow"): usr["flow"] = p["flow"][0]
    st = {"network": net, "security": sec, "sockopt": {"tcpNoDelay": True}}
    if sec == "reality":
        st["realitySettings"] = {
            "fingerprint": fp, "serverName": sni,
            "publicKey": p.get("pbk",[""])[0], "shortId": p.get("sid",[""])[0],
            "spiderX": p.get("spx",["/"])[0],
        }
    elif sec == "tls":
        st["tlsSettings"] = {"serverName": sni, "allowInsecure": False,
                              "fingerprint": fp, "alpn": ["h2","http/1.1"]}
    if net == "ws":   st["wsSettings"]     = {"path": p.get("path",["/"])[0],
                                               "host": p.get("host",[node.host])[0]}
    elif net == "grpc":st["grpcSettings"]  = {"serviceName": p.get("serviceName",[""])[0],
                                              "multiMode": p.get("mode")==["multi"]}
    elif net == "xhttp":st["xhttpSettings"]= {"host": p.get("host",[node.host])[0],
                                              "path": p.get("path",["/"])[0],
                                              "mode": p.get("mode",["auto"])[0]}
    return {"log":{"loglevel":"none"},"dns":{"servers":["localhost"]},
            "inbounds":[{"tag":"s","listen":"127.0.0.1","port":port,
                         "protocol":"socks","settings":{"auth":"noauth","udp":True}}],
            "outbounds":[
                {"tag":"p","protocol":"vless","settings":{"vnext":[{"address":node.host,
                    "port":node.port,"users":[usr]}]},"streamSettings":st,"mux":{"enabled":False}},
                {"tag":"d","protocol":"freedom"}],
            "routing":{"domainStrategy":"AsIs",
                       "rules":[{"type":"field","inboundTag":["s"],"outboundTag":"p",
                                 "network":"udp,tcp"}]}}

def build_trojan_cfg(node, port):
    sni = node.params.get("sni", [node.host])[0]
    fp  = node.params.get("fp", ["chrome"])[0]
    return {"log":{"loglevel":"none"},"dns":{"servers":["localhost"]},
            "inbounds":[{"tag":"s","listen":"127.0.0.1","port":port,
                         "protocol":"socks","settings":{"auth":"noauth","udp":True}}],
            "outbounds":[
                {"tag":"p","protocol":"trojan",
                 "settings":{"servers":[{"address":node.host,"port":node.port,
                                         "password":node.password}]},
                 "streamSettings":{"network":"tcp","security":"tls",
                     "tlsSettings":{"serverName":sni,"allowInsecure":False,
                                    "fingerprint":fp,"alpn":["h2","http/1.1"]},
                     "sockopt":{"tcpNoDelay":True}}},
                {"tag":"d","protocol":"freedom"}],
            "routing":{"domainStrategy":"AsIs",
                       "rules":[{"type":"field","inboundTag":["s"],"outboundTag":"p",
                                 "network":"udp,tcp"}]}}

def build_vmess_cfg(node, port):
    p = node.params
    st = {"network": p.get("type",["tcp"])[0], "sockopt": {"tcpNoDelay": True}}
    if p.get("security",["none"])[0].lower() == "tls":
        st["tlsSettings"] = {"serverName": p.get("sni",[node.host])[0],
                             "allowInsecure": False, "fingerprint": p.get("fp",["chrome"])[0]}
    if st["network"] == "ws":
        st["wsSettings"] = {"path": p.get("path",["/"])[0]}
    elif st["network"] == "grpc":
        st["grpcSettings"] = {"serviceName": p.get("serviceName",[""])[0]}
    return {"log":{"loglevel":"none"},"dns":{"servers":["localhost"]},
            "inbounds":[{"tag":"s","listen":"127.0.0.1","port":port,
                         "protocol":"socks","settings":{"auth":"noauth","udp":True}}],
            "outbounds":[
                {"tag":"p","protocol":"vmess",
                 "settings":{"vnext":[{"address":node.host,"port":node.port,
                                       "users":[{"id":node.uuid,"security":p.get("sec",["auto"])[0]}]}]},
                 "streamSettings":st,"mux":{"enabled":False}},
                {"tag":"d","protocol":"freedom"}],
            "routing":{"domainStrategy":"AsIs",
                       "rules":[{"type":"field","inboundTag":["s"],"outboundTag":"p",
                                 "network":"udp,tcp"}]}}

_CONFIG_BUILDERS = {"vless": build_vless_cfg, "trojan": build_trojan_cfg, "vmess": build_vmess_cfg}
_PORT_NEXT = PORT_BASE


# ═══════════════════════════════════════════════════════════════
# ФАЗА 2 — xray + speedtest
# ═══════════════════════════════════════════════════════════════
async def spawn_xray(cfg_path: str):
    """Запускает xray с конфигом по пути cfg_path."""
    return await asyncio.create_subprocess_exec(
        str(XRAY_EXE), "run", "-c", str(cfg_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

def _wait_port(host, port, timeout=5.0):
    """Синхронная проверка доступности порта (для threading)."""
    import socket
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            s = socket.create_connection((host, port), timeout=0.5)
            s.close()
            return True
        except Exception:
            pass
    return False

async def phase2(nodes: list[Node]):
    """Запускает xray для каждой ноды, проверяет IP и скорость через SOCKS5."""
    sem = asyncio.Semaphore(MAX_XRAY)
    error_count = 0
    diag_done = False

    async def test_one(node: Node) -> tuple:
        nonlocal error_count, diag_done
        async with sem:
            global _PORT_NEXT
            cfg_dict = _CONFIG_BUILDERS.get(node.protocol)
            if not cfg_dict:
                return (node, False, None, None)
            port = _PORT_NEXT; _PORT_NEXT += 1
            cfg = cfg_dict(node, port)
            cfg_file = ASSETS_DIR / f"_cfg_{port}.json"
            cfg_file.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
            proc = None
            try:
                proc = await spawn_xray(cfg_file)
                # ждём пока поднимется порт (до 5 сек)
                started = False
                for _ in range(25):
                    await asyncio.sleep(0.2)
                    try:
                        r, w = await asyncio.wait_for(
                            asyncio.open_connection("127.0.0.1", port), timeout=0.3)
                        w.close(); started = True; break
                    except Exception:
                        pass
                if not started:
                    error_count += 1
                    if not diag_done:
                        try:
                            out, err = await asyncio.gather(
                                proc.stdout.read(), proc.stderr.read())
                            print(f"\n[XRAY DIAG] failed port={port} node={node.host}:{node.port}")
                            print(f"  STDERR: {err.decode(errors='replace')[:400]}")
                            print(f"  STDOUT: {out.decode(errors='replace')[:200]}")
                        except Exception:
                            print(f"[XRAY DIAG] could not read process output, rc={proc.returncode}")
                        diag_done = True
                    return (node, False, None, None, None)

                proxy_host, proxy_port = "127.0.0.1", port

                # ——— Проверка IP через SOCKS5 ———
                ip = None
                try:
                    r, w = await _socks5_connect(proxy_host, proxy_port,
                                                 "ipinfo.io", 80,
                                                 timeout=IP_TIMEOUT)
                    req = (b"GET /ip HTTP/1.1\r\n"
                           b"Host: ipinfo.io\r\n"
                           b"Connection: close\r\n\r\n")
                    w.write(req)
                    await w.drain()
                    buf = b""
                    deadline = time.monotonic() + IP_TIMEOUT
                    while time.monotonic() < deadline:
                        try:
                            chunk = await asyncio.wait_for(r.read(4096), timeout=3)
                            if not chunk: break
                            buf += chunk
                            if b"\r\n\r\n" in buf: break
                        except asyncio.TimeoutError: break
                    text = buf.decode(errors="replace")
                    bs = text.find("\r\n\r\n")
                    if bs >= 0:
                        body = text[bs+4:].strip()
                        if IP_RE.match(body):
                            ip = body
                            print(f"    ip={ip}", flush=True)
                except Exception as e:
                    pass
                finally:
                    try: w.close(); await w.wait_closed()
                    except Exception: pass
                    try: r.close(); await r.wait_closed()
                    except Exception: pass

                # ——— Замер скорости (TTFB → capacity proxy) ———
                speed = None
                if ip:
                    try:
                        t0 = time.monotonic()
                        r, w = await _socks5_connect(proxy_host, proxy_port,
                                                     "cp.cloudflare.com", 80,
                                                     timeout=SPEED_TIMEOUT)
                        req = (b"GET /cdn-cgi/trace HTTP/1.1\r\n"
                               b"Host: cp.cloudflare.com\r\n"
                               b"Connection: close\r\n\r\n")
                        w.write(req)
                        await w.drain()
                        buf = b""
                        deadline = time.monotonic() + SPEED_TIMEOUT
                        while time.monotonic() < deadline:
                            try:
                                chunk = await asyncio.wait_for(r.read(4096), timeout=3)
                                if not chunk: break
                                buf += chunk
                                if b"\r\n\r\n" in buf: break
                            except asyncio.TimeoutError: break
                        elapsed = time.monotonic() - t0
                        bs = buf.find(b"\r\n\r\n")
                        body_len = len(buf) - bs - 4 if bs >= 0 else len(buf)
                        loc = None
                        if body_len > 0:
                            try:
                                text_body = buf[bs+4:].decode(errors="replace")
                                for ln in text_body.splitlines():
                                    if ln.startswith("loc="):
                                        cc = ln[4:6].upper()
                                        if re.match(r"^[A-Z]{2}$", cc):
                                            loc = cc
                                        break
                            except Exception: pass
                        if body_len > 0 and elapsed > 0:
                            est_mbps = int(100 / max(elapsed, 0.1))
                            est_mbps = min(max(est_mbps, 1), 500)
                            speed = est_mbps
                            print(f"    speed={speed}Mbps loc={loc} ({body_len}B/{elapsed:.2f}s)", flush=True)
                    except Exception as e:
                        pass
                    finally:
                        try: w.close(); await w.wait_closed()
                        except Exception: pass
                        try: r.close(); await r.wait_closed()
                        except Exception: pass
                return (node, ip is not None, speed, ip, loc)
            except Exception as e:
                error_count += 1
                return (node, False, None, None, None)
            finally:
                if proc:
                    try:
                        proc.kill()
                        await asyncio.wait_for(proc.wait(), timeout=1.0)
                    except Exception: pass
                try: os.remove(cfg_file)
                except Exception: pass

    tasks = [asyncio.create_task(test_one(n)) for n in nodes]
    done = 0
    pinged, sped = [], []
    for coro in asyncio.as_completed(tasks):
        try:
            node, ok, speed, ip, loc = await coro
        except Exception:
            continue
        done += 1
        if ok: pinged.append((node, ip, loc))
        if speed and speed >= MIN_SPEED: sped.append((node, speed, ip, loc))
        if done % 200 == 0 or done == len(nodes):
            print(f"  [phase2] {done}/{len(nodes)} done, ping={len(pinged)}, speed_ge{MIN_SPEED}={len(sped)}, errs={error_count}", flush=True)
    print(f"\n[phase2 complete] errors_total={error_count}\n")
    return pinged, sped


# ═══════════════════════════════════════════════════════════════
async def geo_phase(alive_nodes):
    """Фильрует ноды по гео через ip-api.com по hostname (не требует прокси)."""
    RU_CODES = {"RU", "XK", "BY", "KP", "SY", "IR", "CU", "VE"}
    non_ru = []
    async with aiohttp.ClientSession() as sess:
        tasks = [(n, asyncio.create_task(
            _check_country(n.host, sess)
        )) for n in alive_nodes]
        done = 0
        for n, coro in tasks:
            cc = await coro
            done += 1
            if cc not in RU_CODES:
                non_ru.append(n)
            if done % 200 == 0 or done == len(alive_nodes):
                print(f"  [geo] {done}/{len(alive_nodes)} checked, foreign={len(non_ru)}", flush=True)
    return non_ru


async def _check_country(host: str, sess: aiohttp.ClientSession) -> str:
    try:
        url = f"http://ip-api.com/json/{host}?fields=countryCode,status,message"
        async with sess.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
            if resp.status != 200:
                return "???"
            data = await resp.json()
            if data.get("status") != "success":
                return "???"
            return data.get("countryCode", "???")
    except Exception:
        return "???"


# ═══════════════════════════════════════════════════════════════
async def main():
    t0 = time.monotonic()
    print(f"\n=== Harvester Lite v2  [{datetime.now().strftime('%H:%M:%S')}] ===\n")
    ASSETS_DIR.mkdir(exist_ok=True)
    BIN_DIR.mkdir(exist_ok=True)
    if not XRAY_EXE.exists():
        print(f"[!] xray.exe missing at {XRAY_EXE}"); sys.exit(1)

    nodes = await collect_nodes(NODES_FILE)
    if not nodes: print("[!] No nodes found"); sys.exit(1)

    # Фаза 1 — TCP ping
    print("[Phase 1] TCP ping …")
    alive = await tcp_phase(nodes)
    print(f"  -> {len(alive)} nodes passed TCP\n")

    # Фаза 2 — xray + speed
    print(f"[Phase 2] Testing {len(alive)} TCP-alive nodes (xray + speed) …\n")
    pinged, sped = await phase2(alive)

    # Сохраняем
    HEADER = "# profile-title:  🌍  RuGlobalNet 🇷🇺"

    def fmt(n: Node, speed=None, ip=None):
        tag = f" | {speed}Mb" if speed else ""
        has_comment = "#" in n.raw and not n.raw.endswith(tag)
        c = "" if has_comment else (f" #{n.comment}" if n.comment else "")
        return f"{n.raw}{c}{tag}".rstrip()

    def write(path, lines):
        path.write_text(HEADER + "\n" + "\n".join(lines), encoding="utf-8")
        print(f"  [output] {path.name}: {len(lines)} entries")

    write(PING_OUT,       [fmt(n, None, ip) for n, ip, _loc in pinged])
    write(SPEED_OUT,      [fmt(n, s, ip) for n, s, ip, _loc in sped])

    # Deduplicate by (protocol, host, port, uuid) — keep first comment
    seen_keys = set()
    deduped = []
    for n, s, ip, loc in sped:
        key = (n.protocol, n.host, n.port, n.uuid)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append((n, s, ip, loc))
    print(f"[i] After dedup: {len(deduped)} / {len(sped)} nodes")

    # Geo-filter: non-RU from speed_tested.txt (loc comes from Cloudflare trace)
    RU_CODES = {"RU", "XK", "BY", "KP", "SY", "IR", "CU", "VE"}
    foreign = [(n, s, ip, loc) for n, s, ip, loc in deduped
               if (loc or "??").upper() not in RU_CODES]
    print(f"  non-RU: {len(foreign)} / {len(deduped)}")
    write(NON_RU_OUT,     [fmt(n, s, ip) for n, s, ip, _loc in foreign])

    dt = time.monotonic() - t0
    print(f"\n=== Done! {dt:.0f}s  tcp_alive={len(alive)}  ping={len(pinged)}  speed>=48={len(sped)}  non_ru={len(foreign)} ===\n")


if __name__ == "__main__":
    asyncio.run(main())
