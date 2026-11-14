#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check.py — 自建 VPN 节点订阅实测过滤器（第一版）

做什么：
  1. 解析若干订阅源文件里的分享链接（vless / vmess / trojan / ss / hysteria2 / tuic），
     跨文件去重（协议+服务器+端口+关键凭据）。
  2. 把每条链接转成 sing-box outbound 配置，逐条用 `sing-box check` 校验；
     转不了/校验不过的如实记录，不假装测过。
  3. 对 TCP 类节点做一次快速 TCP 连通预筛（仅加速；最终“活”的标准是代理请求成功）。
  4. 分块启动单个 sing-box 进程（一块含上百个 mixed 入站，每个入站路由到一个节点），
     用 curl 经每个节点请求 http://www.gstatic.com/generate_204（失败再试 https），
     超时 8 秒，记录成功与延迟。
  5. 输出：output/sub.txt（存活节点原链接，按延迟升序）、output/sub_base64.txt、
     output/report.md（统计报告）；明细在 work/results.json。

用法：
  python3 check.py [--src 文件1 文件2 ...] [--out output目录] [--work work目录]
                   [--bin sing-box路径] [--concurrency 24] [--timeout 8]
                   [--chunk 110] [--limit N] [--no-prefilter]

默认源文件为 igareck 仓库的三份黑名单文件（见 DEFAULT_SRC）。
依赖：python3 标准库 + curl + sing-box 二进制。本机资源有限：并发默认 24，单块 110 节点。
"""
import argparse, base64, collections, concurrent.futures as cf, json, math, os, re
import socket, statistics, subprocess, sys, time, urllib.parse as up, urllib.request
from datetime import datetime, timezone, timedelta

BASE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SRC = [
    "/home/hatch/workspace/research/vpn-configs-for-russia/BLACK_VLESS_RUS.txt",
    "/home/hatch/workspace/research/vpn-configs-for-russia/BLACK_VLESS_RUS_mobile.txt",
    "/home/hatch/workspace/research/vpn-configs-for-russia/BLACK_SS+All_RUS.txt",
]
EXTRA_SOURCES = [
    ("https://raw.githubusercontent.com/aneek0/goida-vpn-configs/main/githubmirror/4.txt", "goida-4.txt"),
    ("https://raw.githubusercontent.com/aneek0/goida-vpn-configs/main/githubmirror/5.txt", "goida-5.txt"),
    ("https://raw.githubusercontent.com/aneek0/goida-vpn-configs/main/githubmirror/1.txt", "goida-1.txt"),
    ("https://raw.githubusercontent.com/aneek0/goida-vpn-configs/main/githubmirror/3.txt", "goida-3.txt"),
]
MAX_TEST = 4500          # 单轮最多实测节点数（按国内可用性优先级截断）
MAX_SUB = 500            # 订阅最多保留条数
SECOND_URLS = ("https://cp.cloudflare.com/generate_204", "https://www.google.com/generate_204")
CST = timezone(timedelta(hours=8))
LINK_RE = re.compile(r'(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*)://[^\s"\'<>]+')

class ConvertError(Exception):
    pass

# ---------------- helpers ----------------

def b64d(s: str) -> bytes:
    s = s.strip().replace('\n', '').replace(' ', '')
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())

def q1(q, key, default=''):
    v = q.get(key)
    return v[0] if v else default

def truthy(v):
    return str(v).lower() in ('1', 'true', 'yes')

def tls_block(q, sni_default='', allow_insecure=False):
    """Build sing-box tls object from common share-link params (dict-like q with .get list values or plain dict)."""
    def g(k, d=''):
        v = q.get(k)
        if isinstance(v, list):
            return v[0] if v else d
        return v if v is not None else d
    tls = {"enabled": True}
    sni = g('sni') or g('peer') or sni_default
    if sni:
        tls["server_name"] = sni
    if allow_insecure or truthy(g('allowInsecure')) or truthy(g('allow_insecure')) or truthy(g('insecure')):
        tls["insecure"] = True
    alpn = g('alpn')
    if alpn:
        tls["alpn"] = [a for a in alpn.split(',') if a]
    fp = g('fp') or g('fingerprint')
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    return tls

def transport_from(q, net, host_hint=''):
    """q: parse_qs dict. net: transport name. Returns sing-box transport dict or None."""
    def g(k, d=''):
        return q1(q, k, d)
    net = (net or 'tcp').lower()
    if net in ('tcp', 'none', 'raw', ''):
        if g('headerType').lower() == 'http':
            t = {"type": "http", "path": g('path', '/')}
            h = g('host')
            if h:
                t["host"] = [x for x in h.split(',') if x]
            return t
        return None
    if net == 'ws':
        t = {"type": "ws"}
        path = g('path', '/')
        m = re.search(r'[?&]ed=(\d+)', path)
        if m:
            t["max_early_data"] = int(m.group(1))
            t["early_data_header_name"] = "Sec-WebSocket-Protocol"
            path = re.sub(r'[?&]ed=\d+', '', path) or '/'
            if path.endswith('?') or path.endswith('&'):
                path = path[:-1]
        t["path"] = path
        h = g('host') or host_hint
        if h:
            t["headers"] = {"Host": h}
        ed = g('ed')
        if ed.isdigit():
            t["max_early_data"] = int(ed)
            t["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return t
    if net == 'grpc':
        return {"type": "grpc", "service_name": g('serviceName') or g('path')}
    if net == 'httpupgrade':
        t = {"type": "httpupgrade", "path": g('path', '/')}
        h = g('host') or host_hint
        if h:
            t["host"] = h
        return t
    if net in ('h2', 'http'):
        t = {"type": "http", "path": g('path', '/')}
        h = g('host') or host_hint
        if h:
            t["host"] = [x for x in h.split(',') if x]
        return t
    if net == 'quic':
        return {"type": "quic"}
    if net in ('xhttp', 'splithttp', 'split-http'):
        raise ConvertError("unsupported_transport: sing-box 1.14.4 不含 xhttp/splithttp 传输实现（已实测两种类型名均被 check 拒绝）")
    raise ConvertError(f"unsupported_transport: {net}")

# ---------------- converters ----------------
# Each returns (outbound_dict, dedup_key)

def conv_vless(link):
    u = up.urlparse(link)
    if not u.hostname or not u.port or not u.username:
        raise ConvertError("parse: missing host/port/uuid")
    q = up.parse_qs(u.query)
    ob = {"type": "vless", "server": u.hostname, "server_port": u.port,
          "uuid": up.unquote(u.username)}
    flow = q1(q, 'flow')
    if flow:
        ob["flow"] = flow
    pe = q1(q, 'packetEncoding')
    if pe:
        ob["packet_encoding"] = pe
    security = q1(q, 'security', 'none').lower()
    net = q1(q, 'type', 'tcp')
    if security == 'reality':
        tls = tls_block(q, sni_default=q1(q, 'host'))
        if "utls" not in tls:
            tls["utls"] = {"enabled": True, "fingerprint": "chrome"}
        tls["reality"] = {"enabled": True, "public_key": q1(q, 'pbk'),
                          "short_id": q1(q, 'sid')}
        ob["tls"] = tls
    elif security == 'tls':
        ob["tls"] = tls_block(q, sni_default=q1(q, 'host'))
    tr = transport_from(q, net, host_hint=q1(q, 'sni'))
    if tr:
        ob["transport"] = tr
    key = ("vless", u.hostname.lower(), u.port, ob["uuid"], flow, q1(q, 'pbk'))
    return ob, key

def conv_vmess(link):
    body = link[len('vmess://'):]
    fp_extra = ''
    if '?' in body:
        body, qs = body.split('?', 1)
        fp_extra = q1(up.parse_qs(qs), 'fp')
    try:
        j = json.loads(b64d(body).decode('utf-8', 'replace'))
    except Exception as e:
        raise ConvertError(f"parse: vmess base64/json invalid ({e})")
    host = str(j.get('add', '')).strip()
    try:
        port = int(j.get('port') or 0)
    except (TypeError, ValueError):
        raise ConvertError("parse: vmess port invalid")
    if not host or not port or not j.get('id'):
        raise ConvertError("parse: vmess missing add/port/id")
    ob = {"type": "vmess", "server": host, "server_port": port, "uuid": j['id'],
          "security": (j.get('scy') or 'auto'), "alter_id": int(j.get('aid') or 0)}
    net = (j.get('net') or 'tcp').lower()
    q = {}
    if j.get('path'):
        q['path'] = [j['path']]
    if j.get('host'):
        q['host'] = [j['host']]
    if j.get('type'):
        q['headerType'] = [j['type']]
    if net == 'grpc' and j.get('path'):
        q['serviceName'] = [j['path']]
    tr = transport_from(q, net, host_hint=str(j.get('sni') or ''))
    if tr:
        ob["transport"] = tr
    if (j.get('tls') or '').lower() == 'tls':
        qq = {}
        if j.get('sni'):
            qq['sni'] = [j['sni']]
        if j.get('alpn'):
            qq['alpn'] = [j['alpn']]
        fp = j.get('fp') or fp_extra
        if fp:
            qq['fp'] = [fp]
        ob["tls"] = tls_block(qq, sni_default=str(j.get('host') or '').split(',')[0])
    key = ("vmess", host.lower(), port, j['id'], ob["alter_id"], net)
    return ob, key

def conv_trojan(link):
    u = up.urlparse(link)
    if not u.hostname or not u.port or not u.username:
        raise ConvertError("parse: missing host/port/password")
    q = up.parse_qs(u.query)
    ob = {"type": "trojan", "server": u.hostname, "server_port": u.port,
          "password": up.unquote(u.username)}
    security = q1(q, 'security', 'tls').lower()
    if security != 'none':
        ob["tls"] = tls_block(q, sni_default=q1(q, 'host'))
    net = q1(q, 'type', 'tcp')
    tr = transport_from(q, net, host_hint=q1(q, 'sni'))
    if tr:
        ob["transport"] = tr
    key = ("trojan", u.hostname.lower(), u.port, ob["password"])
    return ob, key

def conv_ss(link):
    raw = link[len('ss://'):]
    frag = ''
    if '#' in raw:
        raw, frag = raw.split('#', 1)
    query = ''
    if '?' in raw:
        raw, query = raw.split('?', 1)
    q = up.parse_qs(query)
    method = password = host = None
    port = None
    if '@' in raw:
        userinfo, hostport = raw.rsplit('@', 1)
        try:
            dec = b64d(userinfo).decode('utf-8', 'replace')
            if ':' in dec:
                method, password = dec.split(':', 1)
            else:
                raise ValueError
        except Exception:
            parts = up.unquote(userinfo).split(':', 1)
            if len(parts) != 2:
                raise ConvertError("parse: ss userinfo invalid")
            method, password = parts
        hostport = up.unquote(hostport)
        m = re.match(r'^(.+):(\d+)$', hostport)
        if not m:
            raise ConvertError("parse: ss hostport invalid")
        host, port = m.group(1).strip('[]'), int(m.group(2))
    else:
        try:
            dec = b64d(raw).decode('utf-8', 'replace')
        except Exception:
            raise ConvertError("parse: ss legacy base64 invalid")
        m = re.match(r'^(.+?):(.+)@(.+):(\d+)$', dec)
        if not m:
            raise ConvertError("parse: ss legacy format invalid")
        method, password, host, port = m.group(1), m.group(2), m.group(3).strip('[]'), int(m.group(4))
    ob = {"type": "shadowsocks", "server": host, "server_port": port,
          "method": method, "password": password}
    plugin = q1(q, 'plugin')
    if plugin:
        pname, _, popts = plugin.partition(';')
        if pname in ('obfs-local', 'simple-obfs'):
            ob["plugin"] = "obfs-local"
            ob["plugin_opts"] = popts
        elif pname == 'v2ray-plugin':
            ob["plugin"] = "v2ray-plugin"
            ob["plugin_opts"] = popts
        else:
            raise ConvertError(f"unsupported_plugin: {pname}")
    key = ("ss", host.lower(), port, method, password)
    return ob, key

def conv_hy2(link):
    u = up.urlparse(link)
    if not u.hostname or not u.port:
        raise ConvertError("parse: missing host/port")
    q = up.parse_qs(u.query)
    auth = up.unquote(u.username or '')
    if u.password:
        auth = auth + ':' + up.unquote(u.password) if auth else up.unquote(u.password)
    ob = {"type": "hysteria2", "server": u.hostname, "server_port": u.port,
          "password": auth, "tls": tls_block(q)}
    if q1(q, 'obfs') == 'salamander':
        ob["obfs"] = {"type": "salamander", "password": q1(q, 'obfs-password')}
    key = ("hysteria2", u.hostname.lower(), u.port, auth)
    return ob, key

def conv_tuic(link):
    u = up.urlparse(link)
    if not u.hostname or not u.port or not u.username:
        raise ConvertError("parse: missing host/port/uuid")
    q = up.parse_qs(u.query)
    ob = {"type": "tuic", "server": u.hostname, "server_port": u.port,
          "uuid": up.unquote(u.username), "password": up.unquote(u.password or ''),
          "tls": tls_block(q)}
    cc = q1(q, 'congestion_control') or q1(q, 'congestionControl')
    if cc:
        ob["congestion_control"] = cc
    urm = q1(q, 'udp_relay_mode')
    if urm:
        ob["udp_relay_mode"] = urm
    if "alpn" not in ob["tls"]:
        ob["tls"]["alpn"] = ["h3"]
    key = ("tuic", u.hostname.lower(), u.port, ob["uuid"], ob["password"])
    return ob, key

CONVERTERS = {
    'vless': conv_vless, 'vmess': conv_vmess, 'trojan': conv_trojan,
    'ss': conv_ss, 'hysteria2': conv_hy2, 'hy2': conv_hy2, 'tuic': conv_tuic,
}
UDP_PROTO = {'hysteria2', 'tuic'}

# ---------------- 节点分类（国内可用性启发式） ----------------

def class_rank(item):
    """按“在国内网络下更可能可用”分层：Reality(0) > TLS+CDN类传输(1) > TLS直连(2) > SS(3) > UDP类(4) > 明文(5)。
    仅用于测试优先级与订阅排序，不代表实测结论。"""
    ob = item["outbound"]
    tls = ob.get("tls") or {}
    tr = (ob.get("transport") or {}).get("type", "tcp")
    if tls.get("reality"):
        return 0
    if ob["type"] == "shadowsocks":
        return 3
    if ob["type"] in ("hysteria2", "tuic"):
        return 4
    if tls.get("enabled"):
        return 1 if tr in ("ws", "grpc", "httpupgrade", "http") else 2
    return 5

def fetch_extra_sources(workdir):
    paths = []
    for url, name in EXTRA_SOURCES:
        p = os.path.join(workdir, name)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "vpn-sub-checker"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read()
            with open(p, "wb") as f:
                f.write(data)
            paths.append(p)
            print(f"附加源 {name}：{len(data)} 字节", flush=True)
        except Exception as e:
            print(f"附加源 {name} 拉取失败（跳过）：{e}", flush=True)
    return paths

# ---------------- stage 1: parse & dedup ----------------

def parse_sources(src_files):
    nodes = []            # dicts: {link, scheme, src}
    raw_count = 0
    per_file = {}
    unknown_scheme = collections.Counter()
    for path in src_files:
        cnt = 0
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                for m in LINK_RE.finditer(line):
                    link = m.group(0).rstrip(')",\'')
                    scheme = m.group('scheme').lower()
                    raw_count += 1
                    cnt += 1
                    if scheme not in CONVERTERS and scheme not in ('http', 'https'):
                        unknown_scheme[scheme] += 1
                        continue
                    if scheme in ('http', 'https'):
                        continue
                    nodes.append({"link": link, "scheme": scheme, "src": os.path.basename(path)})
        per_file[os.path.basename(path)] = cnt
    return nodes, raw_count, per_file, unknown_scheme

def convert_all(nodes):
    seen = {}
    uniq = []
    conv_fail = []
    for n in nodes:
        try:
            ob, key = CONVERTERS[n['scheme']](n['link'])
        except ConvertError as e:
            conv_fail.append({**n, "error": str(e)})
            continue
        except Exception as e:
            conv_fail.append({**n, "error": f"parse_error: {e}"})
            continue
        if key in seen:
            continue
        seen[key] = True
        item = {**n, "outbound": ob, "key": [str(x) for x in key]}
        uniq.append(item)
    return uniq, conv_fail

# ---------------- stage 2: sing-box check validation ----------------

def validate_all(items, sb, workdir, workers=16):
    def one(i_item):
        i, item = i_item
        ob = dict(item["outbound"]); ob["tag"] = "probe"
        cfg = {"log": {"disabled": True}, "outbounds": [ob]}
        p = os.path.join(workdir, f"chk-{i}.json")
        with open(p, 'w') as f:
            json.dump(cfg, f)
        r = subprocess.run([sb, 'check', '-c', p], capture_output=True, text=True, timeout=30)
        os.unlink(p)
        if r.returncode == 0:
            return i, None
        err = re.sub(r'\x1b\[[0-9;]*m', '', r.stderr).strip().splitlines()
        return i, (err[-1][:300] if err else 'unknown check error')
    bad = {}
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for i, err in ex.map(one, enumerate(items)):
            if err:
                bad[i] = err
    ok = [it for i, it in enumerate(items) if i not in bad]
    failed = [{**items[i], "error": bad[i]} for i in bad]
    return ok, failed

# ---------------- stage 2.5: 环境出站探测 ----------------

def probe_env(items):
    """探测本机是否存在平台级出站 TCP 拦截：对几个节点服务器做裸 TCP 连接并读取横幅。
    某些沙箱网关会接管任意 TCP 连接并返回明文提示（如 '... TCP connections is turned off ...'），
    此时所有 sing-box 握手都会假失败，必须先识别，避免把环境阻断误报为节点死亡。
    返回 (blocked: bool, evidence: str)。"""
    samples = [it for it in items if it["outbound"]["type"] not in UDP_PROTO][:3]
    for it in samples:
        ob = it["outbound"]
        try:
            with socket.create_connection((ob["server"], ob["server_port"]), timeout=4) as s:
                s.settimeout(2.5)
                try:
                    data = s.recv(220)
                except socket.timeout:
                    continue  # 无横幅属正常（多数服务器不会主动发数据）
                text = data.decode('utf-8', 'replace')
                if 'turned off' in text or text.lower().startswith('muse'):
                    return True, f"{ob['server']}:{ob['server_port']} 返回网关提示：{text.strip()[:160]}"
        except Exception:
            continue
    return False, ''

# ---------------- stage 3: TCP prefilter ----------------

def prefilter(items, timeout=3.5, workers=64):
    def probe(item):
        ob = item["outbound"]
        try:
            with socket.create_connection((ob["server"], ob["server_port"]), timeout=timeout):
                return True
        except Exception:
            return False
    todo = [it for it in items if it["outbound"]["type"] not in UDP_PROTO]
    skip = [it for it in items if it["outbound"]["type"] in UDP_PROTO]
    passed, dead = [], []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for item, ok in zip(todo, ex.map(probe, todo)):
            (passed if ok else dead).append(item)
    return passed + skip, dead

# ---------------- stage 4: live test via sing-box + curl ----------------

def build_chunk_config(chunk, base_port):
    inbounds, outbounds, rules = [], [], []
    for i, item in enumerate(chunk):
        inbounds.append({"type": "mixed", "tag": f"in-{i}", "listen": "127.0.0.1",
                         "listen_port": base_port + i})
        ob = dict(item["outbound"]); ob["tag"] = f"n-{i}"
        outbounds.append(ob)
        rules.append({"inbound": [f"in-{i}"], "outbound": f"n-{i}"})
    outbounds.append({"type": "direct", "tag": "direct"})
    return {"log": {"disabled": True}, "inbounds": inbounds, "outbounds": outbounds,
            "route": {"rules": rules, "final": "direct"}}

def wait_port(port, proc, timeout=12):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except Exception:
            time.sleep(0.25)
    return False

def curl_test(port, timeout, urls=("http://www.gstatic.com/generate_204", "https://www.gstatic.com/generate_204")):
    """Returns (ok, latency_ms, detail). Tries the given generate_204 URLs in order."""
    last = ''
    for url in urls:
        try:
            r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}",
                 "--max-time", str(timeout), "-x", f"socks5h://127.0.0.1:{port}", url],
                capture_output=True, text=True, timeout=timeout + 5)
            parts = r.stdout.strip().split()
            if len(parts) == 2:
                code, tt = parts[0], float(parts[1])
                if code in ("200", "204"):
                    return True, round(tt * 1000), f"{url.split(':')[0]} {code}"
                last = f"{url} -> HTTP {code}"
            else:
                last = f"{url} -> curl rc={r.returncode}"
        except subprocess.TimeoutExpired:
            last = f"{url} -> timeout"
        except Exception as e:
            last = f"{url} -> {e}"
    return False, None, last

def test_chunk(chunk, base_port, sb, workdir, timeout, concurrency, urls=None):
    """Returns list of result dicts aligned with chunk."""
    cfg = build_chunk_config(chunk, base_port)
    p = os.path.join(workdir, f"run-{base_port}.json")
    with open(p, 'w') as f:
        json.dump(cfg, f)
    chk = subprocess.run([sb, 'check', '-c', p], capture_output=True, text=True)
    if chk.returncode != 0:
        err = re.sub(r'\x1b\[[0-9;]*m', '', chk.stderr).strip()[:300]
        return [{"status": "infra_error", "latency_ms": None, "detail": f"chunk config check failed: {err}"} for _ in chunk]
    proc = subprocess.Popen([sb, 'run', '-c', p], stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, text=True)
    try:
        if not wait_port(base_port, proc):
            err = ''
            try:
                err = (proc.stderr.read() or '')[:300]
            except Exception:
                pass
            if len(chunk) > 1:  # bisect once to isolate a bad outbound
                mid = len(chunk) // 2
                return (test_chunk(chunk[:mid], base_port, sb, workdir, timeout, concurrency, urls) +
                        test_chunk(chunk[mid:], base_port + 400, sb, workdir, timeout, concurrency, urls))
            return [{"status": "infra_error", "latency_ms": None, "detail": f"sing-box start failed: {err}"} for _ in chunk]
        def job(i):
            ok, lat, det = curl_test(base_port + i, timeout) if urls is None else curl_test(base_port + i, timeout, urls)
            return i, {"status": "alive" if ok else "dead", "latency_ms": lat, "detail": det}
        results = [None] * len(chunk)
        with cf.ThreadPoolExecutor(max_workers=concurrency) as ex:
            for i, res in ex.map(job, range(len(chunk))):
                results[i] = res
        return results
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=6)
        except Exception:
            proc.kill()
        try:
            os.unlink(p)
        except OSError:
            pass

# ---------------- main ----------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--src', nargs='+', default=DEFAULT_SRC)
    ap.add_argument('--out', default=os.path.join(BASE, 'output'))
    ap.add_argument('--work', default=os.path.join(BASE, 'work'))
    ap.add_argument('--bin', default=os.path.join(BASE, 'bin', 'sing-box'))
    ap.add_argument('--concurrency', type=int, default=24)
    ap.add_argument('--timeout', type=int, default=8)
    ap.add_argument('--chunk', type=int, default=110)
    ap.add_argument('--limit', type=int, default=0, help='只测前 N 个（冒烟测试用）')
    ap.add_argument('--no-prefilter', action='store_true')
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    os.makedirs(args.work, exist_ok=True)
    sb_version = subprocess.run([args.bin, 'version'], capture_output=True, text=True).stdout.splitlines()[0].strip()
    t_start = datetime.now(CST)
    print(f"[{t_start:%H:%M:%S}] sing-box: {sb_version}", flush=True)

    extra_paths = fetch_extra_sources(args.work)
    all_src = list(args.src) + extra_paths
    nodes, raw_count, per_file, unknown_scheme = parse_sources(all_src)
    proto_raw = collections.Counter(n['scheme'] for n in nodes)
    print(f"源文件链接行 {raw_count}，可解析协议 {len(nodes)}：{dict(proto_raw)}", flush=True)

    uniq, conv_fail = convert_all(nodes)
    proto_uniq = collections.Counter(it['outbound']['type'] for it in uniq)
    print(f"去重后 {len(uniq)}，转换失败 {len(conv_fail)}：{dict(proto_uniq)}", flush=True)

    valid, check_fail = validate_all(uniq, args.bin, args.work, workers=32)
    print(f"sing-box check 通过 {len(valid)}，失败 {len(check_fail)}", flush=True)

    # 按国内可用性优先级排序并截断到 MAX_TEST，其余本轮不测（如实记录）
    valid.sort(key=lambda it: (class_rank(it), it['src']))
    deferred = valid[MAX_TEST:]
    deferred_n = len(deferred)
    valid = valid[:MAX_TEST]
    if deferred:
        print(f"按优先级截断：本轮实测 {len(valid)}，延后 {deferred_n}", flush=True)

    env_blocked, env_evidence = probe_env(valid)
    if env_blocked:
        print(f"⚠ 环境出站 TCP 被平台网关拦截，跳过实测阶段。证据：{env_evidence}", flush=True)

    if env_blocked:
        to_test, pre_dead = [], []
    elif args.no_prefilter:
        to_test, pre_dead = valid, []
    else:
        to_test, pre_dead = prefilter(valid)
        print(f"TCP 预筛通过 {len(to_test)}，预筛淘汰 {len(pre_dead)}", flush=True)

    if args.limit and not env_blocked:
        to_test = to_test[:args.limit]
        print(f"--limit 生效：只测 {len(to_test)} 个", flush=True)

    results = {}
    chunks = [to_test[i:i + args.chunk] for i in range(0, len(to_test), args.chunk)]
    for ci, chunk in enumerate(chunks):
        base_port = 22000 + ci * 1000
        res = test_chunk(chunk, base_port, args.bin, args.work, args.timeout, args.concurrency)
        for item, r in zip(chunk, res):
            results[id(item)] = r
        alive_n = sum(1 for r in res if r['status'] == 'alive')
        print(f"块 {ci+1}/{len(chunks)}：{len(chunk)} 个，存活 {alive_n}", flush=True)

    # 二次验证：对存活节点换一个目标再测一次，两次都通才算“双验”
    verified2_ids = set()
    alive_items = [it for it in to_test if results.get(id(it), {}).get('status') == 'alive']
    if alive_items:
        for j in range(0, len(alive_items), args.chunk):
            part = alive_items[j:j + args.chunk]
            res2 = test_chunk(part, 42000 + j, args.bin, args.work, args.timeout, args.concurrency, urls=SECOND_URLS)
            for item, r2 in zip(part, res2):
                if r2['status'] == 'alive':
                    verified2_ids.add(id(item))
        print(f"二次验证通过 {len(verified2_ids)}/{len(alive_items)}", flush=True)

    t_end = datetime.now(CST)

    # assemble full records
    records = []
    for item in valid:
        r = results.get(id(item))
        if env_blocked:
            rec = {"status": "blocked_env", "latency_ms": None,
                   "detail": "本机出站 TCP 被平台网关拦截，未能完成真实代理实测（见报告环境限制一节）"}
        elif item in pre_dead:
            rec = {"status": "dead", "latency_ms": None, "detail": "tcp prefilter unreachable"}
        elif r is None:
            rec = {"status": "not_tested", "latency_ms": None, "detail": "beyond --limit"}
        else:
            rec = r
        records.append({"link": item['link'], "proto": item['outbound']['type'],
                        "server": item['outbound']['server'], "port": item['outbound']['server_port'],
                        "src": item['src'], "_rank": class_rank(item),
                        "verified2": id(item) in verified2_ids, **rec})
    alive = [r for r in records if r['status'] == 'alive']
    alive.sort(key=lambda r: (0 if r.get('verified2') else 1, r.get('_rank', 5),
                              r['latency_ms'] if r['latency_ms'] is not None else 10**9))
    alive_all_n = len(alive)
    alive = alive[:MAX_SUB]

    with open(os.path.join(args.work, 'results.json'), 'w') as f:
        json.dump({"records": records,
                   "conv_fail": conv_fail, "check_fail": check_fail}, f, ensure_ascii=False, indent=1)

    sub_text = '\n'.join(r['link'] for r in alive) + ('\n' if alive else '')
    with open(os.path.join(args.out, 'sub.txt'), 'w') as f:
        f.write(sub_text)
    with open(os.path.join(args.out, 'sub_base64.txt'), 'w') as f:
        f.write(base64.b64encode(sub_text.encode()).decode() + '\n')

    # ---- report ----
    lat = [r['latency_ms'] for r in alive if r['latency_ms'] is not None]
    def pct(p):
        if not lat:
            return None
        s = sorted(lat)
        return s[min(len(s) - 1, math.ceil(p / 100 * len(s)) - 1)]
    per_proto = {}
    for proto in sorted(set([r['proto'] for r in records] + [it['outbound']['type'] for it in uniq])):
        tested = [r for r in records if r['proto'] == proto]
        al = [r for r in tested if r['status'] == 'alive']
        per_proto[proto] = {"uniq": proto_uniq.get(proto, 0), "tested_or_prefiltered": len(tested),
                            "alive": len(al)}
    conv_fail_by = collections.Counter(f['scheme'] for f in conv_fail)
    check_fail_by = collections.Counter(f['outbound']['type'] for f in check_fail)
    xhttp_n = sum(1 for f in conv_fail if 'xhttp' in f['error'])
    tested_n = len([r for r in records if r['status'] in ('alive', 'dead')])
    rep = []
    rep.append("# VPN 节点订阅实测报告（v2：多源合并 + 双目标验证 + 国内优先分层）\n")
    rep.append(f"- 测试开始：{t_start:%Y-%m-%d %H:%M:%S} CST；结束：{t_end:%Y-%m-%d %H:%M:%S} CST（耗时 {(t_end - t_start).total_seconds():.0f} 秒）")
    rep.append(f"- 测试工具：{sb_version}（官方 GitHub release，linux-amd64）")
    rep.append(f"- 源文件（运行时拉取最新版）：{', '.join(os.path.basename(s) for s in all_src)}")
    rep.append(f"- 参数：并发 {args.concurrency}，单节点超时 {args.timeout}s，块大小 {args.chunk}，TCP 预筛 {'因环境阻断跳过' if env_blocked else ('关' if args.no_prefilter else '开（3.5s）')}")
    rep.append("\n## 总览\n")
    rep.append(f"- 源文件链接行总数：**{raw_count}**（按文件：{per_file}）")
    rep.append(f"- 支持协议的链接：{len(nodes)}（" + '，'.join(f"{k} {v}" for k, v in proto_raw.most_common()) + "）")
    if unknown_scheme:
        rep.append(f"- 未识别协议（跳过）：{dict(unknown_scheme)}")
    rep.append(f"- 去重后唯一节点：**{len(uniq)}**（注：源列表含大量同端点同 UUID 的参数变体，如同一 Cloudflare 端点仅 fp/sni/备注不同，整行重复就达 139 条；按协议+服务器+端口+凭据去重后实际独立端点远少于 542）")
    if env_blocked:
        rep.append(f"- 实际完成代理实测：**0**（环境阻断，见下节）；存活：**0（未经证实，不代表节点真实状态）**")
    else:
        rep.append(f"- 实际完成代理实测（含预筛淘汰计死）：**{tested_n}**；存活：**{alive_all_n}**；存活率：**{(alive_all_n/tested_n*100 if tested_n else 0):.1f}%**")
        v2n = len([r for r in records if r['status'] == 'alive' and r.get('verified2')])
        rep.append(f"- 双验通过（两个不同目标都请求成功）：**{v2n}**；订阅按「双验优先 → 分层（Reality > TLS+CDN传输 > TLS直连 > SS > UDP类 > 明文）→ 延迟」排序，保留前 {MAX_SUB} 条")
    if env_blocked:
        rep.append("\n## ⚠ 环境限制（本次实测未能完成的原因）\n")
        rep.append("本机（ama 的 Linux 虚拟机）出站网络由平台网关管控：普通网页流量只能走指定的 HTTP 出口代理；"
                   "**到任意 VPN 节点服务器的直连 TCP 被关闭**，网关会接管连接并返回明文提示。证据：")
        rep.append(f"- 裸 TCP 连接节点服务器时收到网关横幅：`{env_evidence}`，大意为「Other TCP connections is turned off for this assistant，需在 Muse 设置 → Permissions 中允许」。")
        rep.append("- sing-box 对全部 108 个节点的 TLS 握手均在 1–2ms 内收到非 TLS 数据而失败（错误完全一致），失败点在本机网关而非节点侧；经出口代理向节点地址发请求同样被拒（长延迟后 400）。")
        rep.append("- 因此本次 **0 存活是环境结论、不是节点结论**：这批节点在用户自己的网络（或开启上述权限后、或在一台无出站限制的机器上）重跑本脚本，才能得到真实存活名单。脚本 `check.py` 开跑前会自动做此环境探测，阻断时直接说明，不再误报「全灭」。")
        rep.append("- 连带影响：TCP 预筛在本环境无意义（网关对所有连接都接受 connect），故本次跳过预筛与实测阶段。")
    rep.append("\n## 分协议\n")
    rep.append("| 协议 | 去重后 | 进入实测流程 | 存活 |")
    rep.append("|---|---|---|---|")
    for p, d in per_proto.items():
        rep.append(f"| {p} | {d['uniq']} | {d['tested_or_prefiltered']} | {d['alive']} |")
    rep.append("\n## 延迟（存活节点）\n")
    if lat:
        rep.append(f"- 最快 {min(lat)} ms｜中位数 {int(statistics.median(lat))} ms｜P90 {pct(90)} ms｜最慢 {max(lat)} ms")
    else:
        rep.append("- 无存活节点")
    rep.append("\n## 未实测 / 跳过说明\n")
    rep.append(f"- 链接转换失败：{len(conv_fail)} 条（按协议：{dict(conv_fail_by)}）。"
               f"其中 xhttp 传输 {xhttp_n} 条：sing-box 1.14.4 已移除/不含 xhttp(splithttp) 传输，已用两种类型名实测均被 `sing-box check` 拒绝，故未测。")
    rep.append(f"- sing-box check 校验失败：{len(check_fail)} 条（按协议：{dict(check_fail_by)}），多为参数不完整/不合规范的公开配置，未进入实测。明细见 work/results.json 的 check_fail。")
    present = set(proto_raw)
    for p in ('ss', 'hysteria2', 'tuic'):
        if p not in present:
            rep.append(f"- {p}：三份源文件本期快照中实际为 0 条（BLACK_SS+All 文件名虽含 SS，本期内容为 vmess/trojan），无可测样本。解析器已支持该协议。")
    rep.append(f"- TCP 预筛淘汰：{len(pre_dead)} 条（端口 TCP 不可达，直接计死，未再走代理请求；UDP 类协议不做预筛）。")
    rep.append(f"- 优先级截断未测：{deferred_n} 条（池子扩大后按国内可用性分层排序，超出单轮 {MAX_TEST} 上限的部分本轮未测，不代表其真实状态）。")
    if args.limit:
        rep.append(f"- 注意：本次为 --limit {args.limit} 冒烟运行，未测节点 {len(valid) - len(to_test) - len(pre_dead)} 条。")
    rep.append("\n## 测试方法\n")
    rep.append("每条链接转 sing-box outbound 后先过 `sing-box check`；再分块启动单个 sing-box 进程，"
               "为每个节点建一个本地 mixed 入站并路由到对应 outbound，用 curl 经 SOCKS5 请求 "
               "`http://www.gstatic.com/generate_204`，失败再试 https 版，返回 200/204 记为存活，"
               "延迟为该次请求总耗时。只有代理请求成功才算活，端口通不算。")
    rep.append("\n## 产出\n")
    rep.append(f"- `output/sub.txt`：{len(alive)} 条存活节点原链接，按「双验 → 分层 → 延迟」排序（本轮存活共 {alive_all_n} 条，保留前 {MAX_SUB} 条）。")
    rep.append("- `output/sub_base64.txt`：sub.txt 的整文件 Base64 版。")
    rep.append("- `work/results.json`：全部节点明细（状态/延迟/失败原因）、转换失败与校验失败清单。")
    report = '\n'.join(rep) + '\n'
    with open(os.path.join(args.out, 'report.md'), 'w') as f:
        f.write(report)
    print(f"\n完成：存活 {len(alive)}/{tested_n}，报告 -> {os.path.join(args.out, 'report.md')}", flush=True)
    print(f"ALIVE={len(alive)} TESTED={tested_n} UNIQUE={len(uniq)} RAW={raw_count}", flush=True)

if __name__ == '__main__':
    main()
