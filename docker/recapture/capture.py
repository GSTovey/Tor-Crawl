#!/usr/bin/env python3
"""Validated PCAP crawler for the 2026-10-28 recapture.

Runs inside a dedicated container:
  pure  : crawler -> mihomo(7890) -> real proxy protocol -> target
  top   : crawler -> Tor(9050) -> mihomo(7890) -> real proxy protocol -> Tor net
  pairs : same as top, capturing lo (pre) and eth0 (post)
  nontor: crawler -> direct -> target

Only requests that satisfy BOTH the HTTP check and the PCAP validator are kept.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
from http.client import HTTPConnection
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pcap_validate

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MODE = os.environ.get("MODE", "pure").strip().lower()
PROTOCOL = os.environ.get("PROTOCOL", "unknown").strip()
BASE_SUBDIR = os.environ.get("BASE_SUBDIR", f"Recapture/{PROTOCOL}").strip()
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "/app/output"))
SITE_LIST = Path(os.environ.get("SITE_LIST", "/app/sites/top1000.txt"))
TARGET_TOTAL = int(os.environ.get("TARGET_TOTAL", "5000"))
MAX_PER_SITE = int(os.environ.get("MAX_PER_SITE", "5"))
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "45" if MODE in ("top", "pairs") else "30"))
POST_WAIT = float(os.environ.get("POST_WAIT", "1.2"))
MAX_BODY = int(os.environ.get("MAX_BODY", str(2 * 1024 * 1024)))
MAX_RETRIES = int(os.environ.get("MAX_RETRIES", "3"))
SWITCH_AFTER = int(os.environ.get("SWITCH_AFTER", "8"))
RUN_HOURS = float(os.environ.get("RUN_HOURS", "72"))
DISK_MIN_GB = float(os.environ.get("DISK_MIN_GB", "50"))
SCHEMES = [s.strip() for s in os.environ.get("SCHEMES", "https,http").split(",") if s.strip()]
PREFLIGHT_URLS = [
    u.strip()
    for u in os.environ.get(
        "PREFLIGHT_URLS",
        "http://cp.cloudflare.com/generate_204,http://www.baidu.com,https://www.baidu.com",
    ).split(",")
    if u.strip()
]
PROXY_PORT = int(os.environ.get("PROXY_PORT", "9050" if MODE in ("top", "pairs") else "7890"))
MIHOMO_API = os.environ.get("MIHOMO_API", "http://127.0.0.1:9091")
MIHOMO_GROUP = os.environ.get("MIHOMO_GROUP", "PROXY")
ALLOWED_UDP = os.environ.get("ALLOWED_UDP", "0") == "1"
try:
    NODE_IDS = json.loads(os.environ.get("NODE_IDS", "[]"))
except Exception:
    NODE_IDS = []
try:
    ALLOWED_PORTS = [
        [int(x[0]), int(x[1])] for x in json.loads(os.environ.get("ALLOWED_PORTS", "[]"))
    ]
except Exception:
    ALLOWED_PORTS = []
try:
    ALLOWED_ENDPOINTS = [
        [str(x[0]), int(x[1])]
        for x in json.loads(os.environ.get("ALLOWED_ENDPOINTS", "[]"))
    ]
except Exception:
    ALLOWED_ENDPOINTS = []

JOB = f"{MODE}__{PROTOCOL or 'nontor'}"
BASE = OUTPUT_DIR / BASE_SUBDIR
META_DIR = OUTPUT_DIR / "_meta"
LOG_DIR = META_DIR / "logs"
PROGRESS_DIR = META_DIR / "progress"
STOP_FILE = Path(os.environ.get("STOP_FILE", str(META_DIR / "STOP")))
META_FILE = META_DIR / f"{JOB}.jsonl"
FAIL_FILE = META_DIR / f"{JOB}_failures.jsonl"
PROGRESS_FILE = PROGRESS_DIR / f"{JOB}.json"

_ORIG_SOCKET = socket.socket
_ORIG_GETADDRINFO = socket.getaddrinfo
_current_node_idx = 0
_current_node = NODE_IDS[0] if NODE_IDS else ""

for d in (BASE, META_DIR, LOG_DIR, PROGRESS_DIR):
    d.mkdir(parents=True, exist_ok=True)
LOG_HANDLE = (LOG_DIR / f"{JOB}.log").open("a", encoding="utf-8", buffering=1)


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} [{JOB}] {msg}"
    print(line, flush=True)
    try:
        LOG_HANDLE.write(line + "\n")
    except Exception:
        pass


def sanitize(name: str) -> str:
    for ch in '<>:"/\\|?*':
        name = name.replace(ch, "_")
    name = name.strip().rstrip(".")
    return name[:180] or "unknown"


def load_sites(path: Path) -> list[str]:
    domains: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            domain = parts[1].strip() if len(parts) >= 2 and parts[0].strip().isdigit() else parts[0].strip()
            if domain:
                domains.append(domain)
    # Preserve order but drop duplicates.
    seen = set()
    out = []
    for d in domains:
        key = d.lower()
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def disk_free_gb() -> float:
    try:
        return shutil.disk_usage(str(OUTPUT_DIR)).free / (1024 ** 3)
    except Exception:
        return 10 ** 9


def wait_port(host: str, port: int, timeout: float) -> bool:
    """Raw TCP probe that works both before and after the pysocks patch."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = _ORIG_SOCKET(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((host, port))
            s.close()
            return True
        except Exception:
            time.sleep(0.4)
    return False


def setup_socks(host: str, port: int) -> None:
    import socks

    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, host, port, rdns=True)
    socket.socket = socks.socksocket
    socket.getaddrinfo = lambda *args, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (args[0], args[1]))
    ]


def local_put(path: str, payload: dict) -> tuple[int, bytes]:
    """PUT to mihomo's loopback controller while the global socket is patched."""
    saved_socket, saved_gai = socket.socket, socket.getaddrinfo
    socket.socket, socket.getaddrinfo = _ORIG_SOCKET, _ORIG_GETADDRINFO
    try:
        conn = HTTPConnection("127.0.0.1", 9091, timeout=4)
        body = json.dumps(payload)
        conn.request("PUT", path, body=body, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data
    finally:
        socket.socket, socket.getaddrinfo = saved_socket, saved_gai


def select_initial_node() -> bool:
    """Verify nodes in order and select the first one that carries a request."""
    global _current_node_idx, _current_node
    if not NODE_IDS:
        return True
    for idx, node in enumerate(NODE_IDS):
        try:
            status, body = local_put(f"/proxies/{MIHOMO_GROUP}", {"name": node})
            if status >= 300:
                log(f"initial node {node}: api {status} {body[:120]!r}")
                continue
            _current_node_idx = idx
            _current_node = node
            # The entrypoint has already bootstrapped Tor (with bridges for
            # ToP/Pairs).  Do not restart it during initial selection.
            last_error = ""
            for url in PREFLIGHT_URLS:
                r = http_get(url, min(REQUEST_TIMEOUT, 20))
                if r["ok"]:
                    log(f"initial node verified: {node} via {url}")
                    return True
                last_error = r["error"]
                time.sleep(0.5)
            log(f"initial node failed: {node}: {last_error}")
        except Exception as exc:
            log(f"initial node error {node}: {exc}")
    return False


def switch_node(reason: str) -> bool:
    global _current_node_idx, _current_node
    if len(NODE_IDS) <= 1:
        return False
    _current_node_idx = (_current_node_idx + 1) % len(NODE_IDS)
    _current_node = NODE_IDS[_current_node_idx]
    try:
        status, body = local_put(
            f"/proxies/{MIHOMO_GROUP}", {"name": _current_node}
        )
        log(f"switch node -> {_current_node} (api {status}) reason={reason}")
        if status >= 300:
            log(f"switch failed body={body[:200]!r}")
            return False
    except Exception as exc:
        log(f"switch failed: {exc}")
        return False

    if MODE in ("top", "pairs"):
        if not restart_tor():
            raise SystemExit(5)
    else:
        # Verify the new node with a tiny request.
        for _ in range(3):
            r = http_get("http://cp.cloudflare.com/generate_204", 12)
            if r["ok"]:
                return True
            time.sleep(2)
        log("new node did not pass verification; will keep cycling")
    return True


def restart_tor() -> bool:
    """Restart the Tor process after switching the underlying node."""
    pid_file = Path("/tmp/tor.pid")
    try:
        if pid_file.is_file():
            pid = int(pid_file.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            time.sleep(1.5)
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
    except Exception:
        pass
    try:
        proc = subprocess.Popen(
            ["tor", "-f", "/tmp/torrc"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        pid_file.write_text(str(proc.pid), encoding="utf-8")
    except Exception as exc:
        log(f"tor restart failed to start: {exc}")
        return False
    if not wait_port("127.0.0.1", 9050, 90):
        log("tor restart: port 9050 not ready")
        return False
    for attempt in range(3):
        r = http_get("http://cp.cloudflare.com/generate_204", 20)
        if r["ok"]:
            log("tor restart verified")
            return True
        time.sleep(3)
    log("tor restart: verification failed")
    return False


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def http_get(url: str, timeout: int) -> dict:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/126.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
    }
    req = Request(url, headers=headers)
    t0 = time.monotonic()
    try:
        with urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
            status = int(resp.status)
            try:
                data = resp.read(MAX_BODY + 1)
                body_len = len(data)
                body_error = None
            except Exception as exc:
                body_len = 0
                body_error = str(exc)[:120]
            return {
                "ok": 200 <= status < 400,
                "status": status,
                "body_len": body_len,
                "body_error": body_error,
                "error": None,
                "duration": round(time.monotonic() - t0, 3),
                "final_url": resp.geturl(),
            }
    except HTTPError as exc:
        try:
            exc.read(8192)
        except Exception:
            pass
        return {
            "ok": False,
            "status": exc.code,
            "body_len": 0,
            "body_error": None,
            "error": f"HTTP {exc.code}",
            "duration": round(time.monotonic() - t0, 3),
            "final_url": url,
        }
    except (URLError, socket.timeout, TimeoutError, ssl.SSLError, OSError) as exc:
        return {
            "ok": False,
            "status": None,
            "body_len": 0,
            "body_error": None,
            "error": str(getattr(exc, "reason", exc))[:160],
            "duration": round(time.monotonic() - t0, 3),
            "final_url": url,
        }
    except Exception as exc:
        return {
            "ok": False,
            "status": None,
            "body_len": 0,
            "body_error": None,
            "error": str(exc)[:160],
            "duration": round(time.monotonic() - t0, 3),
            "final_url": url,
        }


# ---------------------------------------------------------------------------
# tcpdump
# ---------------------------------------------------------------------------
POST_FILTER = "not port 53 and (tcp or udp)"
PRE_FILTER = "tcp and port 7890"
NONTOR_FILTER = "tcp and not port 53"


def start_tcpdump(iface: str, path: Path, bpf: str) -> subprocess.Popen:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    proc = subprocess.Popen(
        ["tcpdump", "-i", iface, "-w", str(path), "-s", "0", "-U", "-n", bpf],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    # Fast proxy nodes can finish a request in <100 ms.  Wait until tcpdump has
    # created the pcap global header and settled, otherwise the whole request
    # can be missed (observed with VLESS/AnyTLS/Hysteria2 pilot captures).
    for _ in range(60):
        if proc.poll() is not None:
            raise RuntimeError(f"tcpdump exited early on {iface}")
        if path.exists() and path.stat().st_size >= 24:
            break
        time.sleep(0.1)
    time.sleep(0.8)
    if proc.poll() is not None:
        raise RuntimeError(f"tcpdump exited early on {iface}")
    return proc


def stop_tcpdump(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    if proc.poll() is None:
        try:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
                proc.wait(timeout=2)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Validation / counts
# ---------------------------------------------------------------------------
def validate(path: Path, vmode: str) -> dict:
    try:
        return pcap_validate.parse_pcap(
            path,
            vmode,
            PROTOCOL,
            ALLOWED_PORTS,
            ALLOWED_UDP,
            7890,
            ALLOWED_ENDPOINTS,
        )
    except Exception as exc:
        return {"valid": False, "reasons": [f"validator_error:{exc}"], "summary": {}}


def count_existing(site_dir: Path) -> int:
    if not site_dir.is_dir():
        return 0
    if MODE == "pairs":
        return sum(1 for p in site_dir.glob("*_post.pcap") if p.is_file())
    return sum(1 for p in site_dir.glob("*.pcap") if p.is_file())


def total_existing(sites: list[str]) -> int:
    total = 0
    for domain in sites:
        total += count_existing(BASE / sanitize(domain))
        if total >= TARGET_TOTAL:
            return total
    return total


def write_progress(state: dict) -> None:
    try:
        tmp = PROGRESS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, PROGRESS_FILE)
    except Exception:
        pass


def append_jsonl(path: Path, obj: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# One slot (one pcap / one pair)
# ---------------------------------------------------------------------------
def capture_slot(site_dir: Path, index: int, domain: str) -> dict:
    if MODE == "pairs":
        final_post = site_dir / f"{index:03d}_post.pcap"
        final_pre = site_dir / f"{index:03d}_pre.pcap"
        temp_post = site_dir / f".{index:03d}_post.pcap.part"
        temp_pre = site_dir / f".{index:03d}_pre.pcap.part"
    else:
        final_post = site_dir / f"{index:03d}.pcap"
        temp_post = site_dir / f".{index:03d}.pcap.part"
        final_pre = temp_pre = None

    last = {
        "valid": False,
        "errors": [],
        "http": None,
        "post": None,
        "pre": None,
        "scheme": None,
        "pcap_size": 0,
    }

    for scheme in SCHEMES:
        url = f"{scheme}://{domain}/"
        post_proc = None
        pre_proc = None
        try:
            post_proc = start_tcpdump(
                "eth0", temp_post, NONTOR_FILTER if MODE == "nontor" else POST_FILTER
            )
            if MODE == "pairs":
                pre_proc = start_tcpdump("lo", temp_pre, PRE_FILTER)
        except Exception as exc:
            for p in (pre_proc, post_proc):
                if p:
                    stop_tcpdump(p)
            last["errors"].append(f"tcpdump:{exc}")
            continue

        http = http_get(url, REQUEST_TIMEOUT)
        time.sleep(POST_WAIT)
        stop_tcpdump(pre_proc)
        stop_tcpdump(post_proc)

        last["http"] = http
        last["scheme"] = scheme

        if not http["ok"]:
            last["errors"].append(f"{scheme}:{http['error']}")
            for p in (temp_pre, temp_post):
                if p and p.exists():
                    p.unlink()
            continue

        post_val = validate(temp_post, "nontor" if MODE == "nontor" else "post")
        last["post"] = post_val
        if MODE == "pairs":
            pre_val = validate(temp_pre, "pre")
            last["pre"] = pre_val
            valid = pre_val["valid"] and post_val["valid"]
            reasons = []
            if not pre_val["valid"]:
                reasons.append("pre:" + ",".join(pre_val["reasons"]))
            if not post_val["valid"]:
                reasons.append("post:" + ",".join(post_val["reasons"]))
        else:
            valid = post_val["valid"]
            reasons = list(post_val["reasons"])

        if not valid:
            last["errors"].append(f"{scheme}:pcap_invalid:" + "|".join(reasons))
            for p in (temp_pre, temp_post):
                if p and p.exists():
                    p.unlink()
            continue

        # Success: publish files atomically.
        try:
            os.replace(temp_post, final_post)
            if MODE == "pairs" and final_pre is not None:
                os.replace(temp_pre, final_pre)
        except Exception as exc:
            last["errors"].append(f"rename:{exc}")
            for p in (temp_pre, temp_post):
                if p and p.exists():
                    p.unlink()
            continue

        last["valid"] = True
        last["pcap_size"] = final_post.stat().st_size
        if MODE == "pairs" and final_pre is not None:
            last["pcap_size"] += final_pre.stat().st_size
        return last

    return last


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    log(
        f"start mode={MODE} protocol={PROTOCOL} target={TARGET_TOTAL} "
        f"max/site={MAX_PER_SITE} nodes={len(NODE_IDS)} "
        f"allowed_ports={ALLOWED_PORTS} udp={ALLOWED_UDP}"
    )
    if MODE == "nontor":
        log("direct mode: no Tor, no proxy")
    else:
        if not wait_port("127.0.0.1", PROXY_PORT, 60):
            log(f"ERROR: proxy port {PROXY_PORT} not ready")
            return 2
        setup_socks("127.0.0.1", PROXY_PORT)
        if not select_initial_node():
            log("ERROR: no selected node passed the preflight request")
            return 6
        log(f"proxy path verified via 127.0.0.1:{PROXY_PORT}")

    sites = load_sites(SITE_LIST)
    if not sites:
        log("ERROR: empty site list")
        return 1
    sites = [sanitize(d) for d in sites]

    captured = total_existing(sites)
    log(f"sites={len(sites)} existing_valid={captured}")
    if captured >= TARGET_TOTAL:
        log("target already reached")
        return 0

    started = time.time()
    attempts = 0
    failed_attempts = 0
    consecutive_failures = 0
    sites_done = 0
    last_error = ""
    stop_reason = ""
    state = {
        "job": JOB,
        "mode": MODE,
        "protocol": PROTOCOL,
        "target": TARGET_TOTAL,
        "captured": captured,
        "attempts": attempts,
        "sites_done": sites_done,
        "sites_total": len(sites),
        "current_site": "",
        "current_node": _current_node,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "updated_at": "",
        "elapsed_s": 0,
        "last_error": "",
        "stop_reason": "",
    }

    for site_idx, domain in enumerate(sites):
        if captured >= TARGET_TOTAL:
            stop_reason = "target"
            break
        if STOP_FILE.exists():
            stop_reason = "stop_file"
            break
        if RUN_HOURS > 0 and time.time() - started > RUN_HOURS * 3600:
            stop_reason = "time_cap"
            break
        if disk_free_gb() < DISK_MIN_GB:
            stop_reason = "disk_low"
            break

        site_dir = BASE / domain
        site_dir.mkdir(parents=True, exist_ok=True)
        existing = count_existing(site_dir)
        if existing >= MAX_PER_SITE:
            sites_done += 1
            continue

        for slot in range(existing, MAX_PER_SITE):
            if captured >= TARGET_TOTAL:
                break
            if STOP_FILE.exists():
                stop_reason = "stop_file"
                break
            if disk_free_gb() < DISK_MIN_GB:
                stop_reason = "disk_low"
                break

            index = slot + 1
            result = None
            for retry in range(MAX_RETRIES):
                attempts += 1
                result = capture_slot(site_dir, index, domain)
                if result["valid"]:
                    break
                failed_attempts += 1
                consecutive_failures += 1
                last_error = " | ".join(result["errors"])[:500]
                append_jsonl(
                    FAIL_FILE,
                    {
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                        "domain": domain,
                        "index": index,
                        "retry": retry,
                        "node": _current_node,
                        "scheme": result.get("scheme"),
                        "http": result.get("http"),
                        "errors": result["errors"],
                    },
                )
                if consecutive_failures >= SWITCH_AFTER and len(NODE_IDS) > 1:
                    switch_node(f"{consecutive_failures}_consecutive_failures")
                    consecutive_failures = 0
                time.sleep(0.5 + 0.5 * retry)

            if result and result["valid"]:
                captured += 1
                consecutive_failures = 0
                append_jsonl(
                    META_FILE,
                    {
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                        "job": JOB,
                        "mode": MODE,
                        "protocol": PROTOCOL,
                        "domain": domain,
                        "index": index,
                        "site_slot": slot,
                        "http": result.get("http"),
                        "scheme": result.get("scheme"),
                        "node": _current_node,
                        "pcap_bytes": result.get("pcap_size"),
                        "validator_post": result.get("post"),
                        "validator_pre": result.get("pre"),
                        "files": (
                            [f"{index:03d}_pre.pcap", f"{index:03d}_post.pcap"]
                            if MODE == "pairs"
                            else [f"{index:03d}.pcap"]
                        ),
                    },
                )
                log(
                    f"[{site_idx+1}/{len(sites)}] {domain} #{index:03d} OK "
                    f"{result['scheme']} HTTP {result['http']['status']} "
                    f"{result['pcap_size']}B node={_current_node}"
                )
            else:
                log(
                    f"[{site_idx+1}/{len(sites)}] {domain} #{index:03d} FAIL "
                    f"{last_error[:160]}"
                )
                break

        sites_done += 1
        state.update(
            {
                "captured": captured,
                "attempts": attempts,
                "sites_done": sites_done,
                "current_site": domain,
                "current_node": _current_node,
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "elapsed_s": round(time.time() - started, 1),
                "last_error": last_error,
                "stop_reason": stop_reason,
            }
        )
        write_progress(state)
        if stop_reason:
            break

    state.update(
        {
            "captured": captured,
            "attempts": attempts,
            "sites_done": sites_done,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "elapsed_s": round(time.time() - started, 1),
            "last_error": last_error,
            "stop_reason": stop_reason or "finished",
        }
    )
    write_progress(state)
    log(
        f"done captured={captured}/{TARGET_TOTAL} attempts={attempts} "
        f"failed={failed_attempts} sites={sites_done}/{len(sites)} stop={state['stop_reason']}"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:
        log(f"FATAL: {exc!r}")
        raise
