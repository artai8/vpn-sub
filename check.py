#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自建 VPN 节点订阅检测器 v3（融合版）。

融合两个项目的优点：
- 本项目 v2：igareck + goida 大节点池（链接格式）、按“国内可用性”分层
  （Reality > TLS+CDN 传输 > TLS 直连 > SS > UDP 类 > 明文）、双目标验证、
  如实报告（去重/截断/未测都明示）。
- free-proxy-airport v7（sunmiao4458）：4 个 Clash 原生节点源（主+备地址）、
  用 mihomo 内核自带的 delay 接口测速（一个进程测全部节点，支持
  xhttp/ssr 等 sing-box 测不了的协议）、Clash 智能分组输出
  （AUTO/HK/JP/SG/US/AI 池 + FALLBACK + AI 域名分流）、自愈
  （本轮无可用节点时不覆盖旧订阅）。

流程：多源抓取（链接清单 + Clash YAML）→ 统一转 Clash proxy 字典 →
指纹去重 → 分层排序截断 → mihomo delay 双目标实测 → 输出
output/sub.txt、output/sub_base64.txt、output/clash.yaml、output/report.md。
只有经代理的真实 HTTP 请求成功才算存活。
"""
import argparse, base64, collections, concurrent.futures as cf, gzip, hashlib, json, os, re
import shutil, socket, subprocess, sys, tempfile, time, urllib.parse as up, urllib.request
from datetime import datetime, timezone, timedelta

try:
    import yaml
except ImportError:  # workflow 未装时自举（pip --target 到 work/vendor）
    yaml = None

CST = timezone(timedelta(hours=8))
UA = {"User-Agent": "vpn-sub-checker/3.0"}

DEFAULT_SRC = [
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "..", "Downloads", "v2rayse", "BLACK_VLESS_RUS.txt"),
]
LINK_RE = re.compile(
    r'(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|socks5)://[^\s"\'<>`]+', re.I)
TRAILING = ')"\',<>，。；;]'

# goida 聚合（链接格式），按“对国内用户的价值”排序：Reality 密集的小文件在前
EXTRA_LINK_SOURCES = [
    ("https://raw.githubusercontent.com/aneek0/goida-vpn-configs/main/githubmirror/4.txt", "goida-4.txt"),
    ("https://raw.githubusercontent.com/aneek0/goida-vpn-configs/main/githubmirror/5.txt", "goida-5.txt"),
    ("https://raw.githubusercontent.com/aneek0/goida-vpn-configs/main/githubmirror/1.txt", "goida-1.txt"),
    ("https://raw.githubusercontent.com/aneek0/goida-vpn-configs/main/githubmirror/3.txt", "goida-3.txt"),
]
# free-proxy-airport 的 4 个 Clash 原生源（主 + 备）
CLASH_SOURCES = [
    {"name": "openRunner",
     "urls": ["https://raw.githubusercontent.com/openRunner/clash-freenode/main/sub.yaml",
              "https://raw.githubusercontent.com/openRunner/clash-freenode/main/clash.yaml"]},
    {"name": "snakem982",
     "urls": ["https://raw.githubusercontent.com/snakem982/proxypool/main/clash.yaml",
              "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta-2.yaml",
              "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta.yaml"]},
    {"name": "Flikify",
     "urls": ["https://raw.githubusercontent.com/Flikify/Free-Node/main/clash.yaml",
              "https://raw.githubusercontent.com/a2470982985/getNode/main/clash.yaml",
              "https://cdn.jsdelivr.net/gh/a2470982985/getNode@main/clash.yaml"]},
    {"name": "free-clash-v2ray",
     "urls": ["https://free-clash-v2ray.github.io/uploads/latest.yaml"],
     "discover": "https://raw.githubusercontent.com/free-clash-v2ray/free-clash-v2ray.github.io/main/README.md"},
]
SUPPORTED_TYPES = {"ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2",
                   "tuic", "socks5", "http", "anytls"}
MAX_TEST = 8000        # 单轮最多实测（mihomo delay 很快，可以比 sing-box 时代大）
MAX_SUB = 500          # 订阅最多保留条数
MIN_ALIVE = 30         # 自愈阈值：低于此数视为本轮异常，不覆盖旧输出
TARGET1 = "http://www.gstatic.com/generate_204"
TARGET2 = "https://cp.cloudflare.com/generate_204"


def fetch_bytes(url, timeout=30, retries=2):
    last = None
    for a in range(retries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:
            last = e
            time.sleep(1 + a)
    raise RuntimeError(f"fetch failed {url}: {last}")


def fetch_text(url, timeout=30, retries=2):
    return fetch_bytes(url, timeout, retries).decode("utf-8", errors="replace")


def maybe_b64(text):
    compact = "".join(text.split())
    if compact and len(compact) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        try:
            dec = base64.b64decode(compact, validate=True).decode("utf-8")
            if "://" in dec or "proxies:" in dec:
                return dec
        except Exception:
            pass
    return text


def ensure_yaml(workdir):
    global yaml
    if yaml is not None:
        return True
    vendor = os.path.join(workdir, "vendor")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--quiet",
                        "--target", vendor, "pyyaml"], check=True,
                       capture_output=True, timeout=180)
        sys.path.insert(0, vendor)
        import yaml as _y
        yaml = _y
        return True
    except Exception as e:
        print(f"pyyaml 自举失败：{e}", flush=True)
        return False


# ---------------- 地区识别（借鉴 free-proxy-airport，按节点名判断） ----------------

_REGION_PATTERNS = {
    "HK": [r"\bhk\b", r"\bhkg\b", "hong kong", "香港", "🇭🇰"],
    "JP": [r"\bjp\b", r"\bjpn\b", "japan", "日本", "🇯🇵"],
    "SG": [r"\bsg\b", r"\bsgp\b", "singapore", "新加坡", "🇸🇬"],
    "US": [r"\bus\b", r"\busa\b", "united states", "america", "美国", "🇺🇸"],
    "TW": [r"\btw\b", "taiwan", "台湾", "🇹🇼"],
    "KR": [r"\bkr\b", "korea", "韩国", "🇰🇷"],
}

def detect_region(name):
    t = (name or "").lower()
    for region, pats in _REGION_PATTERNS.items():
        for p in pats:
            if p.startswith("\\") or "\\b" in p:
                if re.search(p, t):
                    return region
            elif p in t:
                return region
    return "OTHER"


# ---------------- 分层（国内可用性启发式，基于 Clash 字典） ----------------

def tier_of(proxy):
    t = proxy.get("type")
    if proxy.get("reality-opts"):
        return 0
    if t == "shadowsocks" or t == "ss":
        return 3
    if t in ("hysteria2", "hysteria", "tuic"):
        return 4
    tls = bool(proxy.get("tls")) or t in ("trojan", "anytls")
    net = str(proxy.get("network") or "tcp").lower()
    if tls:
        return 1 if net in ("ws", "grpc", "h2", "httpupgrade", "http") else 2
    return 5


BRAND_SNIS = {
    "www.apple.com", "apple.com", "www.cloudflare.com", "cloudflare.com",
    "aws.amazon.com", "amazon.com", "www.amazon.com", "www.microsoft.com",
    "microsoft.com", "www.google.com", "google.com", "www.yahoo.com",
    "yahoo.com", "www.sony.co.uk", "www.bing.com", "bing.com", "fuck.rkn",
}

def _is_ip(s):
    try:
        import ipaddress
        ipaddress.ip_address(str(s))
        return True
    except Exception:
        return False

def cn_risk_pattern(proxy):
    """用户手机实测（2026-11-15）得出的国内高风险模式：不通的 7 个节点无一例外是
    「裸 IP 服务器 + 大牌 SNI（apple/cloudflare/amazon 等）+ Reality vision 流」；
    能通的 47 个里只有 1 个命中该组合。命中的节点在排序时压到最后。"""
    sni = str(proxy.get("servername") or proxy.get("sni") or "").lower()
    return (_is_ip(proxy.get("server")) and sni in BRAND_SNIS
            and proxy.get("flow") == "xtls-rprx-vision")

def fingerprint(proxy):
    important = {k: proxy.get(k) for k in
                 ("type", "server", "port", "uuid", "password", "cipher", "network",
                  "servername", "sni")}
    if proxy.get("reality-opts"):
        important["pbk"] = proxy["reality-opts"].get("public-key")
    payload = json.dumps(important, sort_keys=True, ensure_ascii=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------- 链接解析 → Clash proxy 字典 ----------------

def b64d(s):
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s).decode("utf-8", "replace")


def split_link(link):
    proto, rest = link.split("://", 1)
    frag = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)
    return proto.lower(), rest, up.parse_qs(query), up.unquote(frag)


def q1(params, *names):
    for n in names:
        v = params.get(n)
        if v and v[0]:
            return v[0]
    return ""


def apply_transport(proxy, params):
    net = (q1(params, "type", "net") or "tcp").lower()
    if net in ("tcp", ""):
        return
    proxy["network"] = net
    if net == "ws":
        opts = {}
        path = q1(params, "path")
        host = q1(params, "host")
        if path:
            opts["path"] = path
        if host:
            opts["headers"] = {"Host": host}
        if opts:
            proxy["ws-opts"] = opts
    elif net == "grpc":
        sn = q1(params, "serviceName", "servicename", "service-name")
        if sn:
            proxy["grpc-opts"] = {"grpc-service-name": sn}
    elif net in ("h2", "http"):
        opts = {}
        path = q1(params, "path")
        host = q1(params, "host")
        if path:
            opts["path"] = [path]
        if host:
            opts["host"] = [host]
        if opts:
            proxy["h2-opts" if net == "h2" else "http-opts"] = opts


def conv_vless(link):
    _, rest, params, frag = split_link(link)
    if "@" not in rest:
        return None
    uuid, hostport = rest.rsplit("@", 1)
    server, port = hostport.rsplit(":", 1)
    p = {"name": frag or f"vless-{server}", "type": "vless", "server": server,
         "port": int(port), "uuid": uuid, "udp": True}
    security = (q1(params, "security") or "none").lower()
    sni = q1(params, "sni", "servername", "peer")
    if sni:
        p["servername"] = sni
    fp = q1(params, "fp", "fingerprint")
    if fp:
        p["client-fingerprint"] = fp
    if security == "reality":
        p["tls"] = True
        ro = {}
        pbk = q1(params, "pbk", "public-key")
        sid = q1(params, "sid", "short-id")
        if pbk:
            ro["public-key"] = pbk
        if sid:
            ro["short-id"] = sid
        if not ro:
            return None
        p["reality-opts"] = ro
    elif security == "tls":
        p["tls"] = True
    flow = q1(params, "flow")
    if flow:
        p["flow"] = flow
    if q1(params, "allowInsecure") in ("1", "true"):
        p["skip-cert-verify"] = True
    apply_transport(p, params)
    return p


def conv_vmess(link):
    _, rest, _, _ = split_link(link)
    try:
        j = json.loads(b64d(rest.split("?")[0].split("#")[0]))
    except Exception:
        return None
    p = {"name": str(j.get("ps") or f"vmess-{j.get('add')}"), "type": "vmess",
         "server": str(j.get("add") or ""), "port": int(j.get("port") or 0),
         "uuid": str(j.get("id") or ""), "alterId": int(j.get("aid") or 0),
         "cipher": str(j.get("scy") or "auto"), "udp": True}
    if not p["server"] or not p["port"] or not p["uuid"]:
        return None
    net = str(j.get("net") or "tcp").lower()
    if j.get("tls") == "tls":
        p["tls"] = True
    sni = str(j.get("sni") or "")
    if sni:
        p["servername"] = sni
    if net != "tcp":
        p["network"] = net
        host, path = str(j.get("host") or ""), str(j.get("path") or "")
        if net == "ws":
            opts = {}
            if path:
                opts["path"] = path
            if host:
                opts["headers"] = {"Host": host}
            if opts:
                p["ws-opts"] = opts
        elif net == "grpc":
            if path:
                p["grpc-opts"] = {"grpc-service-name": path}
        elif net in ("h2", "http"):
            opts = {}
            if path:
                opts["path"] = [path]
            if host:
                opts["host"] = [host]
            if opts:
                p["h2-opts" if net == "h2" else "http-opts"] = opts
    return p


def conv_trojan(link):
    _, rest, params, frag = split_link(link)
    if "@" not in rest:
        return None
    password, hostport = rest.rsplit("@", 1)
    server, port = hostport.rsplit(":", 1)
    p = {"name": frag or f"trojan-{server}", "type": "trojan", "server": server,
         "port": int(port), "password": up.unquote(password), "udp": True}
    sni = q1(params, "sni", "peer")
    if sni:
        p["sni"] = sni
    if q1(params, "allowInsecure") in ("1", "true"):
        p["skip-cert-verify"] = True
    apply_transport(p, params)
    return p


def conv_ss(link):
    _, rest, _, frag = split_link(link)
    rest = rest.split("?")[0]
    plugin = None
    if "@" in rest:
        userinfo, hostport = rest.rsplit("@", 1)
        if ":" not in userinfo:
            try:
                userinfo = b64d(userinfo)
            except Exception:
                return None
    else:
        try:
            dec = b64d(rest)
        except Exception:
            return None
        if "@" not in dec:
            return None
        userinfo, hostport = dec.rsplit("@", 1)
    if ":" not in userinfo or ":" not in hostport:
        return None
    cipher, password = userinfo.split(":", 1)
    server, port = hostport.rsplit(":", 1)
    return {"name": frag or f"ss-{server}", "type": "ss", "server": server,
            "port": int(port), "cipher": cipher, "password": up.unquote(password),
            "udp": True}


def conv_hy2(link):
    _, rest, params, frag = split_link(link)
    if "@" not in rest:
        return None
    auth, hostport = rest.rsplit("@", 1)
    server, port = hostport.rsplit(":", 1)
    p = {"name": frag or f"hy2-{server}", "type": "hysteria2", "server": server,
         "port": int(port), "password": up.unquote(auth), "udp": True}
    sni = q1(params, "sni", "peer")
    if sni:
        p["sni"] = sni
    if q1(params, "insecure") in ("1", "true"):
        p["skip-cert-verify"] = True
    obfs = q1(params, "obfs")
    if obfs:
        p["obfs"] = obfs
        p["obfs-password"] = q1(params, "obfs-password")
    return p


def conv_tuic(link):
    _, rest, params, frag = split_link(link)
    if "@" not in rest:
        return None
    userinfo, hostport = rest.rsplit("@", 1)
    server, port = hostport.rsplit(":", 1)
    if ":" in userinfo:
        uuid, password = userinfo.split(":", 1)
    else:
        uuid, password = userinfo, ""
    p = {"name": frag or f"tuic-{server}", "type": "tuic", "server": server,
         "port": int(port), "uuid": uuid, "password": up.unquote(password), "udp": True}
    sni = q1(params, "sni")
    if sni:
        p["sni"] = sni
    alpn = q1(params, "alpn")
    if alpn:
        p["alpn"] = [alpn]
    if q1(params, "allow_insecure", "allowInsecure") in ("1", "true"):
        p["skip-cert-verify"] = True
    return p


CONVERTERS = {"vless": conv_vless, "vmess": conv_vmess, "trojan": conv_trojan,
              "ss": conv_ss, "hysteria2": conv_hy2, "hy2": conv_hy2, "tuic": conv_tuic}


def parse_link_text(text, src_name):
    """Returns (nodes, raw_link_count, per-proto counts, conv_fail counts)."""
    links = LINK_RE.findall(text)
    nodes, fails = [], collections.Counter()
    protos = collections.Counter()
    for link in links:
        link = link.rstrip(TRAILING)
        proto = link.split("://", 1)[0].lower()
        protos[proto] += 1
        conv = CONVERTERS.get(proto)
        if conv is None:
            fails[proto] += 1
            continue
        try:
            proxy = conv(link)
        except Exception:
            proxy = None
        if not proxy or not proxy.get("server") or not proxy.get("port"):
            fails[proto] += 1
            continue
        nodes.append({"proxy": proxy, "link": link, "src": src_name,
                      "name0": str(proxy.get("name") or "")})
    return nodes, len(links), protos, fails


# ---------------- Clash YAML 源 ----------------

def extract_yaml_proxies(text):
    doc = yaml.safe_load(maybe_b64(text))
    proxies = []
    if isinstance(doc, dict) and isinstance(doc.get("proxies"), list):
        proxies = doc["proxies"]
    elif isinstance(doc, list):
        proxies = doc
    return [p for p in proxies if isinstance(p, dict)]


def normalize_yaml_proxy(raw):
    p = {k: v for k, v in raw.items() if v is not None}
    t = str(p.get("type", "")).lower().strip()
    if t == "hy2":
        t = "hysteria2"
    if t == "ss":
        t = "ss"
    if t not in SUPPORTED_TYPES:
        return None
    p["type"] = "ss" if t == "ss" else t
    server = str(p.get("server", "")).strip()
    if not server:
        return None
    try:
        port = int(p.get("port"))
    except Exception:
        return None
    if not (0 < port <= 65535):
        return None
    p["server"], p["port"] = server, port
    p.setdefault("name", f"{t}-{server}")
    if "udp" not in p:
        p["udp"] = True
    return p


def collect_clash_sources():
    nodes, stats = [], {}
    for group in CLASH_SOURCES:
        urls = list(group["urls"])
        if group.get("discover"):
            try:
                readme = fetch_text(group["discover"])
                found = re.findall(
                    r"https://free-clash-v2ray\.github\.io/uploads/\d{4}/\d{2}/[0-9]-\d{8}\.yaml",
                    readme)
                for u in found[:8]:
                    if u not in urls:
                        urls.append(u)
            except Exception as e:
                print(f"源 {group['name']} discover 失败：{e}", flush=True)
        got = []
        for url in urls:
            try:
                text = fetch_text(url)
                raw = extract_yaml_proxies(text)
                got = [n for n in (normalize_yaml_proxy(r) for r in raw) if n]
                if got:
                    break
            except Exception as e:
                print(f"源 {group['name']} 拉取失败 {url}：{e}", flush=True)
        stats[group["name"]] = len(got)
        for proxy in got:
            nodes.append({"proxy": proxy, "link": None, "src": group["name"],
                          "name0": str(proxy.get("name") or "")})
        print(f"Clash 源 {group['name']}：{len(got)} 个节点", flush=True)
    return nodes, stats


# ---------------- mihomo 引擎 ----------------

def provision_mihomo(bin_path, workdir):
    if bin_path and os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
        return bin_path
    cache = os.path.join(workdir, "mihomo")
    os.makedirs(workdir, exist_ok=True)
    if os.path.isfile(cache) and os.access(cache, os.X_OK):
        return cache
    print("下载 mihomo 内核（MetaCubeX/mihomo 最新版）...", flush=True)
    api = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
    data = json.loads(fetch_text(api))
    asset_url, fallback = None, None
    for a in data.get("assets", []):
        name = str(a.get("name", "")).lower()
        if "linux" not in name or "amd64" not in name or not name.endswith(".gz"):
            continue
        if name.endswith(".tar.gz"):
            continue
        if "compatible" in name:
            asset_url = a["browser_download_url"]
        elif fallback is None:
            fallback = a["browser_download_url"]
    url = asset_url or fallback
    if not url:
        raise RuntimeError("mihomo release 里找不到 linux-amd64 资源")
    raw = fetch_bytes(url, timeout=120)
    blob = gzip.decompress(raw)
    with open(cache, "wb") as f:
        f.write(blob)
    os.chmod(cache, 0o755)
    print(f"mihomo 已就绪：{cache}（{len(blob)} 字节）", flush=True)
    return cache


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def probe_env(nodes):
    """直连任意节点做 TCP 握手；若收到平台网关的明文提示，判定环境拦截。"""
    evidence = ""
    for node in nodes[:40]:
        p = node["proxy"]
        try:
            with socket.create_connection((p["server"], int(p["port"])), timeout=4) as s:
                s.settimeout(1.5)
                try:
                    data = s.recv(200)
                except socket.timeout:
                    data = b""
                if data and (b"turned off" in data or b"muse" in data.lower()):
                    evidence = data.decode("utf-8", "replace").strip()[:160]
                    return True, f"{p['server']}:{p['port']} 返回网关提示：{evidence}"
                return False, ""
        except Exception:
            continue
    return False, ""


def delay_once(ctrl, name, url, timeout_ms):
    q = up.urlencode({"timeout": timeout_ms, "url": url})
    req = urllib.request.Request(f"{ctrl}/proxies/{up.quote(name, safe='')}/delay?{q}")
    try:
        with urllib.request.urlopen(req, timeout=timeout_ms / 1000 + 4) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        d = int(data.get("delay") or 0)
        return d if d > 0 else None
    except Exception:
        return None


def bench_chunk(chunk, engine, workdir, concurrency, timeout_ms):
    """chunk: list of node dicts with proxy['name'] preset to a unique test name.
    Returns {id(node): (latency_ms, verified2)} for nodes passing target1.
    Raises RuntimeError if mihomo fails to boot with this chunk."""
    tmp = tempfile.mkdtemp(prefix="bench-", dir=workdir)
    ctrl_port = free_port()
    proxies = [dict(n["proxy"]) for n in chunk]
    names = [p["name"] for p in proxies]
    cfg = {"mixed-port": free_port(), "allow-lan": False, "mode": "rule",
           "log-level": "warning", "external-controller": f"127.0.0.1:{ctrl_port}",
           "proxies": proxies,
           "proxy-groups": [{"name": "BENCH", "type": "select", "proxies": names}],
           "rules": ["MATCH,BENCH"]}
    cfg_path = os.path.join(tmp, "config.yaml")
    with open(cfg_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
    proc = subprocess.Popen([engine, "-d", tmp, "-f", cfg_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ctrl = f"http://127.0.0.1:{ctrl_port}"
    try:
        ready = False
        for _ in range(40):
            if proc.poll() is not None:
                raise RuntimeError("mihomo exited during startup")
            try:
                with urllib.request.urlopen(f"{ctrl}/version", timeout=1) as r:
                    if r.status == 200:
                        ready = True
                        break
            except Exception:
                time.sleep(0.5)
        if not ready:
            raise RuntimeError("mihomo controller not ready")
        results = {}

        def job(node):
            name = node["proxy"]["name"]
            lat = delay_once(ctrl, name, TARGET1, timeout_ms)
            if lat is None:
                return node, None
            lat2 = delay_once(ctrl, name, TARGET2, timeout_ms)
            return node, (lat, lat2 is not None)

        with cf.ThreadPoolExecutor(max_workers=concurrency) as ex:
            for node, res in ex.map(job, chunk):
                if res is not None:
                    results[id(node)] = res
        return results
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        shutil.rmtree(tmp, ignore_errors=True)


def benchmark(nodes, engine, workdir, concurrency, timeout_s, chunk_size=1200):
    """Returns (alive_map, engine_fail_count). alive_map: id(node) -> (latency, verified2)."""
    alive, engine_fail = {}, 0
    for start in range(0, len(nodes), chunk_size):
        chunk = nodes[start:start + chunk_size]
        stack = [chunk]
        while stack:
            part = stack.pop()
            try:
                res = bench_chunk(part, engine, workdir, concurrency, int(timeout_s * 1000))
                alive.update(res)
            except RuntimeError:
                if len(part) == 1:
                    engine_fail += 1
                else:
                    mid = len(part) // 2
                    stack.append(part[:mid])
                    stack.append(part[mid:])
        print(f"实测进度 {min(start + chunk_size, len(nodes))}/{len(nodes)}，"
              f"存活累计 {len(alive)}，引擎拒绝 {engine_fail}", flush=True)
    return alive, engine_fail


# ---------------- Clash proxy → 分享链接（给 sub.txt 用） ----------------

def proxy_to_link(p, display_name):
    t = p.get("type")
    name = up.quote(display_name or p.get("name") or t)
    server, port = p.get("server"), p.get("port")
    try:
        if t == "vless":
            params = {"encryption": "none"}
            ro = p.get("reality-opts")
            if ro:
                params["security"] = "reality"
                params["pbk"] = ro.get("public-key", "")
                if ro.get("short-id"):
                    params["sid"] = ro["short-id"]
            elif p.get("tls"):
                params["security"] = "tls"
            else:
                params["security"] = "none"
            if p.get("servername"):
                params["sni"] = p["servername"]
            if p.get("client-fingerprint"):
                params["fp"] = p["client-fingerprint"]
            if p.get("flow"):
                params["flow"] = p["flow"]
            net = p.get("network")
            if net:
                params["type"] = net
                if net == "ws":
                    opts = p.get("ws-opts") or {}
                    if opts.get("path"):
                        params["path"] = opts["path"]
                    host = ((opts.get("headers") or {}).get("Host"))
                    if host:
                        params["host"] = host
                elif net == "grpc":
                    sn = (p.get("grpc-opts") or {}).get("grpc-service-name")
                    if sn:
                        params["serviceName"] = sn
            if p.get("skip-cert-verify"):
                params["allowInsecure"] = "1"
            return f"vless://{p['uuid']}@{server}:{port}?{up.urlencode(params)}#{name}"
        if t == "vmess":
            j = {"v": "2", "ps": display_name or "", "add": server, "port": str(port),
                 "id": p.get("uuid", ""), "aid": str(p.get("alterId") or 0),
                 "scy": p.get("cipher") or "auto", "net": p.get("network") or "tcp",
                 "type": "none", "host": "", "path": "", "tls": "", "sni": ""}
            if p.get("tls"):
                j["tls"] = "tls"
            if p.get("servername"):
                j["sni"] = p["servername"]
            net = p.get("network")
            if net == "ws":
                opts = p.get("ws-opts") or {}
                j["path"] = opts.get("path") or ""
                j["host"] = ((opts.get("headers") or {}).get("Host")) or ""
            elif net == "grpc":
                j["path"] = (p.get("grpc-opts") or {}).get("grpc-service-name") or ""
            raw = json.dumps(j, ensure_ascii=False, separators=(",", ":"))
            return "vmess://" + base64.b64encode(raw.encode()).decode()
        if t == "trojan":
            params = {}
            if p.get("sni"):
                params["sni"] = p["sni"]
            net = p.get("network")
            if net:
                params["type"] = net
                if net == "ws":
                    opts = p.get("ws-opts") or {}
                    if opts.get("path"):
                        params["path"] = opts["path"]
                    host = ((opts.get("headers") or {}).get("Host"))
                    if host:
                        params["host"] = host
            if p.get("skip-cert-verify"):
                params["allowInsecure"] = "1"
            qs = f"?{up.urlencode(params)}" if params else ""
            return f"trojan://{up.quote(str(p.get('password', '')), safe='')}@{server}:{port}{qs}#{name}"
        if t == "ss":
            cred = base64.urlsafe_b64encode(
                f"{p.get('cipher')}:{p.get('password')}".encode()).decode().rstrip("=")
            return f"ss://{cred}@{server}:{port}#{name}"
        if t == "hysteria2":
            params = {}
            if p.get("sni"):
                params["sni"] = p["sni"]
            if p.get("skip-cert-verify"):
                params["insecure"] = "1"
            if p.get("obfs"):
                params["obfs"] = p["obfs"]
                params["obfs-password"] = p.get("obfs-password") or ""
            qs = f"?{up.urlencode(params)}" if params else ""
            return f"hysteria2://{up.quote(str(p.get('password', '')), safe='')}@{server}:{port}{qs}#{name}"
        if t == "tuic":
            params = {}
            if p.get("sni"):
                params["sni"] = p["sni"]
            if p.get("alpn"):
                params["alpn"] = ",".join(p["alpn"])
            if p.get("skip-cert-verify"):
                params["allow_insecure"] = "1"
            qs = f"?{up.urlencode(params)}" if params else ""
            return f"tuic://{p.get('uuid', '')}:{up.quote(str(p.get('password', '')), safe='')}@{server}:{port}{qs}#{name}"
    except Exception:
        return None
    return None


# ---------------- 输出 ----------------

def build_clash_config(alive_nodes):
    """alive_nodes: list of node dicts already sorted (verified2, tier, latency),
    each with proxy + display name assigned in proxy['name']."""
    proxies = [n["proxy"] for n in alive_nodes]
    names = [p["name"] for p in proxies]
    by_region = collections.defaultdict(list)
    for n in alive_nodes:
        by_region[n["region"]].append(n["proxy"]["name"])

    def pool(region):
        lst = by_region.get(region) or []
        return lst if lst else names[:min(5, len(names))]

    ai_size = min(max(3, len(alive_nodes) // 5), 30, len(alive_nodes))
    by_lat = sorted(alive_nodes, key=lambda n: n["latency"])
    ai_names = [n["proxy"]["name"] for n in by_lat[:ai_size]]
    test_url = TARGET1
    groups = [
        {"name": "AUTO-FAST", "type": "url-test", "proxies": names,
         "url": test_url, "interval": 300},
        {"name": "HK-POOL", "type": "url-test", "proxies": pool("HK"),
         "url": test_url, "interval": 300},
        {"name": "JP-POOL", "type": "url-test", "proxies": pool("JP"),
         "url": test_url, "interval": 300},
        {"name": "SG-POOL", "type": "url-test", "proxies": pool("SG"),
         "url": test_url, "interval": 300},
        {"name": "US-POOL", "type": "url-test", "proxies": pool("US"),
         "url": test_url, "interval": 300},
        {"name": "AI-POOL", "type": "url-test", "proxies": ai_names,
         "url": test_url, "interval": 300},
        {"name": "FALLBACK", "type": "fallback",
         "proxies": ["AUTO-FAST", "HK-POOL", "JP-POOL", "US-POOL"],
         "url": test_url, "interval": 300},
        {"name": "PROXY", "type": "select",
         "proxies": ["AUTO-FAST", "FALLBACK", "HK-POOL", "JP-POOL", "SG-POOL", "US-POOL", "AI-POOL"]},
    ]
    rules = [
        "DOMAIN-SUFFIX,openai.com,AI-POOL",
        "DOMAIN-SUFFIX,chatgpt.com,AI-POOL",
        "DOMAIN-SUFFIX,claude.ai,AI-POOL",
        "DOMAIN-SUFFIX,anthropic.com,AI-POOL",
        "GEOIP,CN,DIRECT",
        "MATCH,PROXY",
    ]
    return {"mixed-port": 7890, "allow-lan": True, "mode": "rule",
            "log-level": "info", "ipv6": True, "unified-delay": True,
            "tcp-concurrent": True, "global-client-fingerprint": "chrome",
            "generated-by": "vpn-sub-checker-v3",
            "generated-at": datetime.now(timezone.utc).isoformat(),
            "proxies": proxies, "proxy-groups": groups, "rules": rules}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", nargs="+", default=DEFAULT_SRC)
    ap.add_argument("--out", default="output")
    ap.add_argument("--work", default="work")
    ap.add_argument("--bin", default="bin/mihomo")
    ap.add_argument("--concurrency", type=int, default=48)
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    os.makedirs(args.work, exist_ok=True)
    t_start = datetime.now(CST)
    if not ensure_yaml(args.work):
        print("无 yaml 库，Clash 源与配置输出不可用，退出", flush=True)
        return 1

    # ---- 收集：链接源（igareck 参数文件 + goida 附加源） ----
    all_nodes, src_stats = [], {}
    per_proto, conv_fails = collections.Counter(), collections.Counter()
    link_files = list(args.src)
    for url, name in EXTRA_LINK_SOURCES:
        p = os.path.join(args.work, name)
        try:
            data = fetch_bytes(url, timeout=30)
            with open(p, "wb") as f:
                f.write(data)
            link_files.append(p)
            print(f"附加链接源 {name}：{len(data)} 字节", flush=True)
        except Exception as e:
            print(f"附加链接源 {name} 拉取失败（跳过）：{e}", flush=True)
    raw_links = 0
    for path in link_files:
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except Exception as e:
            print(f"源文件读不到 {path}：{e}", flush=True)
            continue
        nodes, n_raw, protos, fails = parse_link_text(text, os.path.basename(path))
        raw_links += n_raw
        per_proto.update(protos)
        conv_fails.update(fails)
        src_stats[os.path.basename(path)] = len(nodes)
        all_nodes.extend(nodes)
    # ---- 收集：Clash YAML 源 ----
    clash_nodes, clash_stats = collect_clash_sources()
    src_stats.update(clash_stats)
    all_nodes.extend(clash_nodes)

    # ---- 去重 + 分层 ----
    seen, uniq = set(), []
    for node in all_nodes:
        fp = fingerprint(node["proxy"])
        if fp in seen:
            continue
        seen.add(fp)
        node["tier"] = tier_of(node["proxy"])
        node["region"] = detect_region(node["name0"])
        uniq.append(node)
    dup_n = len(all_nodes) - len(uniq)
    uniq.sort(key=lambda n: (n["tier"], n["src"]))
    deferred = uniq[MAX_TEST:]
    to_test = uniq[:MAX_TEST]
    if args.limit:
        to_test = to_test[:args.limit]
    print(f"合并 {len(all_nodes)}，去重后 {len(uniq)}（重复 {dup_n}），"
          f"本轮实测 {len(to_test)}，延后 {len(deferred)}", flush=True)

    # ---- 环境探测 ----
    env_blocked, env_evidence = probe_env(to_test)
    alive_map, engine_fail = {}, 0
    if env_blocked:
        print(f"⚠ 环境出站 TCP 被平台网关拦截，跳过实测。证据：{env_evidence}", flush=True)
    else:
        engine = provision_mihomo(args.bin, args.work)
        for i, node in enumerate(to_test):
            node["proxy"] = dict(node["proxy"])
            node["proxy"]["name"] = f"T{i:05d}"
        alive_map, engine_fail = benchmark(to_test, engine, args.work,
                                           args.concurrency, args.timeout)
    t_end = datetime.now(CST)

    # ---- 汇总存活 ----
    alive = []
    for node in to_test:
        res = alive_map.get(id(node))
        if res:
            lat, v2 = res
            node["latency"], node["verified2"] = lat, v2
            alive.append(node)
    # 排序：国内高风险模式压底 → 双验 → 分层 → 域名服务器优先 → 443 优先 → 延迟
    # （域名/443 偏好同样来自用户实测：能通组域名占比 43% vs 池子 17%，443 占比 85% vs 64%）
    alive.sort(key=lambda n: (1 if cn_risk_pattern(n["proxy"]) else 0,
                              0 if n["verified2"] else 1, n["tier"],
                              1 if _is_ip(n["proxy"].get("server")) else 0,
                              0 if n["proxy"].get("port") == 443 else 1,
                              n["latency"]))
    alive_all_n = len(alive)
    kept = alive[:MAX_SUB]
    # 分配可读名字（原始备注优先，重名加后缀）
    used = set()
    for i, node in enumerate(kept):
        base = (node["name0"] or "").strip() or f"{node['proxy']['type']}-{node['proxy']['server']}"
        name, k = base, 2
        while name in used:
            name = f"{base}-{k}"
            k += 1
        used.add(name)
        node["proxy"]["name"] = name
        node["display"] = name

    # ---- 自愈：存活太少说明本轮异常，不覆盖旧输出 ----
    if alive_all_n < MIN_ALIVE and not env_blocked:
        print(f"⚠ 本轮存活 {alive_all_n} < 自愈阈值 {MIN_ALIVE}，保留旧订阅，不写出新文件。",
              flush=True)
        return 0

    # ---- 写出 ----
    links, link_skip = [], 0
    for node in kept:
        link = node["link"] or proxy_to_link(node["proxy"], node["display"])
        if link:
            links.append(link)
        else:
            link_skip += 1
    with open(os.path.join(args.out, "sub.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(links) + ("\n" if links else ""))
    with open(os.path.join(args.out, "sub_base64.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode(("\n".join(links)).encode()).decode() + "\n")
    clash_cfg = build_clash_config(kept)
    with open(os.path.join(args.out, "clash.yaml"), "w", encoding="utf-8") as f:
        yaml.safe_dump(clash_cfg, f, allow_unicode=True, sort_keys=False)

    # ---- 报告 ----
    tested_n = len(to_test)
    v2n = sum(1 for n in alive if n["verified2"])
    lat_list = sorted(n["latency"] for n in alive)

    def pct(p):
        if not lat_list:
            return 0
        return lat_list[min(len(lat_list) - 1, int(len(lat_list) * p))]

    per_t = collections.defaultdict(lambda: [0, 0, 0])   # tier -> 去重后/实测/存活
    for n in uniq:
        per_t[n["tier"]][0] += 1
    for n in to_test:
        per_t[n["tier"]][1] += 1
    for n in alive:
        per_t[n["tier"]][2] += 1
    tier_names = {0: "Reality", 1: "TLS+CDN传输", 2: "TLS直连", 3: "SS", 4: "UDP类(hy2/tuic)", 5: "明文/其他"}
    rep = []
    rep.append("# VPN 节点订阅实测报告（v4：v3 + 按用户实测反馈的国内风险模式压底）\n")
    rep.append(f"- 测试开始：{t_start:%Y-%m-%d %H:%M:%S} CST；结束：{t_end:%Y-%m-%d %H:%M:%S} CST"
               f"（耗时 {int((t_end - t_start).total_seconds())} 秒）")
    rep.append(f"- 测试引擎：mihomo（MetaCubeX）delay 接口，双目标 {TARGET1} + {TARGET2}")
    rep.append(f"- 来源统计（解析后节点数）：{src_stats}")
    rep.append("")
    rep.append("## 总览\n")
    rep.append(f"- 链接源原始链接：**{raw_links}**（协议分布 {dict(per_proto)}）；合并全部来源后节点 {len(all_nodes)}")
    rep.append(f"- 去重后唯一节点：**{len(uniq)}**（重复 {dup_n}）")
    if env_blocked:
        rep.append(f"- ⚠ **实测未执行**：运行环境出站 TCP 被平台网关拦截。证据：{env_evidence}")
        rep.append("- 本轮存活数不可信（记为 0），下方分层表仅为池子构成。")
    else:
        rep.append(f"- 实际实测：**{tested_n}**；存活：**{alive_all_n}**；存活率："
                   f"**{(alive_all_n / tested_n * 100 if tested_n else 0):.1f}%**")
        rep.append(f"- 双验通过：**{v2n}**；订阅按「双验 → 分层 → 延迟」排序，保留前 {MAX_SUB} 条")
        pat_alive = sum(1 for n in alive if cn_risk_pattern(n["proxy"]))
        pat_kept = sum(1 for n in kept if cn_risk_pattern(n["proxy"]))
        rep.append(f"- 国内高风险模式（裸IP+大牌SNI+vision，用户实测 7/7 不通）：存活 {pat_alive} 个，"
                   f"排序已压底，入选订阅 {pat_kept} 个（仅在其他节点不足 {MAX_SUB} 时补位）")
        if lat_list:
            rep.append(f"- 延迟（存活）：最快 {lat_list[0]} ms｜中位数 {pct(0.5)} ms｜P90 {pct(0.9)} ms｜最慢 {lat_list[-1]} ms")
    rep.append("")
    rep.append("## 分层（去重后 / 实测 / 存活）\n")
    rep.append("| 层 | 去重后 | 实测 | 存活 |")
    rep.append("|---|---|---|---|")
    for tier in sorted(per_t):
        a, b, c = per_t[tier]
        rep.append(f"| {tier} {tier_names.get(tier, '')} | {a} | {b} | {c} |")
    rep.append("")
    rep.append("## 未实测 / 跳过说明\n")
    rep.append(f"- 链接转换失败/不支持：{sum(conv_fails.values())} 条（{dict(conv_fails)}；含 ssr/socks5 等未实现链接解析的协议，"
               f"这类节点若来自 Clash 源仍会被测）。")
    rep.append(f"- mihomo 引擎拒绝（配置不合法被隔离剔除）：{engine_fail} 条。")
    rep.append(f"- 优先级截断未测：{len(deferred)} 条（超出单轮 {MAX_TEST} 上限的低层节点，本轮未测，不代表其真实状态）。")
    rep.append(f"- 存活但无法生成分享链接（仅 Clash 版包含）：{link_skip} 条。")
    rep.append("")
    rep.append("## 测试方法\n")
    rep.append("全部候选写入一份 mihomo 配置启动内核，逐个调用其 delay 接口经该节点请求目标 URL，"
               "返回有效延迟记为通过；通过者再换第二个目标复测（双验）。只有真实代理请求成功才算活。")
    rep.append("")
    rep.append("## 产出\n")
    rep.append(f"- `output/sub.txt`：{len(links)} 条存活节点分享链接（风险模式压底 → 双验 → 分层 → 域名/443 优先 → 延迟）。")
    rep.append("- `output/sub_base64.txt`：sub.txt 的整文件 Base64 版。")
    rep.append(f"- `output/clash.yaml`：完整 Clash 配置（{len(kept)} 个节点 + AUTO/HK/JP/SG/US/AI 分组 + FALLBACK + AI 域名分流规则）。")
    with open(os.path.join(args.out, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(rep) + "\n")
    print(f"完成：存活 {alive_all_n}/{tested_n}（双验 {v2n}），订阅 {len(links)} 条，"
          f"报告 -> {os.path.join(args.out, 'report.md')}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
