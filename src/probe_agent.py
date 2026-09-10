#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_agent.py — 大陆拨测探针（每 30 分钟计划任务 Web4-ProbeAgent）

流程:
  1. GET Worker /api/internal/probe-queue?token= → 待拨测 URL 队列
  2. 逐个直连拨测（主大陆出口，SSRF 防护: 拒绝内网/环回目标）
  3. POST /api/internal/probe-result 回写结果 → 买家重新 GET 获得结果

日志: D:\logs\ai-bg\web4-probe-agent.log
"""
import io
import ipaddress
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

BASE = os.path.dirname(os.path.abspath(__file__))
WORKER = "https://web4shop-x402.web4shop-7023.workers.dev"
TOKEN_FILE = os.path.join(BASE, ".secrets", "sentinel_token.txt")
LOG_FILE = r"D:\logs\ai-bg\web4-probe-agent.log"
PROXY = "http://127.0.0.1:10809"  # 仅用于访问 Worker API；拨测本身直连

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def log(msg):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def http_api(url, method="GET", body=None, timeout=25):
    """经代理访问 Worker 内部端点"""
    handlers = [urllib.request.ProxyHandler({"http": PROXY, "https": PROXY})]
    opener = urllib.request.build_opener(*handlers)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"User-Agent": "web4-probe-agent", "Content-Type": "application/json"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return None, str(e).encode()


def guard_private(url):
    """SSRF 防护: 只允许公网 http(s) 目标"""
    from urllib.parse import urlparse
    try:
        u = urlparse(url)
        if u.scheme not in ("http", "https"):
            return False, "scheme not allowed"
        host = u.hostname or ""
        if not host:
            return False, "no host"
        if host in ("localhost",) or host.endswith(".local") or host.endswith(".internal"):
            return False, "local host"
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False, "private address"
        return True, host
    except Exception as e:
        return False, f"resolve failed: {e}"


def probe(url, timeout=10):
    """直连拨测（主大陆出口，不走代理）: DNS→TCP→TLS→HTTP"""
    from urllib.parse import urlparse
    u = urlparse(url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    out = {"status": "ok", "http_code": None, "latency_s": None, "error_class": None}
    t0 = time.time()
    try:
        socket.getaddrinfo(host, port)
    except OSError:
        out.update(status="dns_fail", error_class="dns")
        return out
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except socket.timeout:
        out.update(status="connection_failed", error_class="timeout",
                   latency_s=round(time.time() - t0, 3))
        return out
    except OSError as e:
        cls = "connection_reset" if "reset" in str(e).lower() or "10054" in str(e) else "refused"
        out.update(status="connection_failed", error_class=cls,
                   latency_s=round(time.time() - t0, 3))
        return out
    try:
        if u.scheme == "https":
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 web4-probe\r\nConnection: close\r\n\r\n"
        sock.sendall(req.encode())
        first = sock.recv(64).decode("latin1", errors="replace")
        out["http_code"] = first.split(" ")[1] if first.startswith("HTTP") else None
        out["latency_s"] = round(time.time() - t0, 3)
    except socket.timeout:
        out["status"] = "partial_degraded"
        out["error_class"] = "timeout"
    except OSError:
        out["status"] = "partial_degraded"
        out["error_class"] = "timeout"
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return out


def main():
    if not os.path.exists(TOKEN_FILE):
        log("缺少令牌文件，退出")
        return 1
    token = open(TOKEN_FILE, encoding="utf-8").read().strip()

    code, raw = http_api(f"{WORKER}/api/internal/probe-queue?token={token}")
    if code != 200:
        log(f"取队列失败: HTTP {code} {raw[:120]}")
        return 1
    queue = json.loads(raw).get("queue", [])
    log(f"队列: {len(queue)} 个 URL")
    if not queue:
        return 0

    done = 0
    for url in queue:
        ok, info = guard_private(url)
        if not ok:
            log(f"跳过 {url} ({info})")
            result = {"status": "rejected", "error_class": "target_not_allowed"}
        else:
            result = probe(url)
            log(f"拨测 {url} -> {result['status']} {result.get('http_code')}")
        code, _ = http_api(f"{WORKER}/api/internal/probe-result?token={token}",
                           method="POST", body={"url": url, "result": result})
        if code == 200:
            done += 1
        else:
            log(f"回写失败 HTTP {code}")
        time.sleep(2)
    log(f"完成 {done}/{len(queue)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
