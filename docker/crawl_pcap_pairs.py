#!/usr/bin/env python3
"""
Dual PCAP capture for ToP traffic pairs:
  _pre.pcap  : lo interface (Tor → Xray SOCKS5, post-Tor pre-proxy)
  _post.pcap : eth0 interface (Xray → remote server, post-proxy)

Architecture:
  crawl → Tor SOCKS5(9050) → Xray SOCKS5(1080) → eth0 → remote
           └── lo capture ──┘                  └── eth0 capture ──┘
              (_pre.pcap)                         (_post.pcap)
"""
import os, sys, time, signal, socket, subprocess, csv
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

PROTOCOL = os.environ.get("PROTOCOL", "unknown")
MAX_PCAPS = int(os.environ.get("MAX_PCAPS", "10"))
TARGET_TOTAL = int(os.environ.get("TARGET_TOTAL", "10000"))
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "30"))
TOR_HOST = os.environ.get("TOR_HOST", "127.0.0.1")
TOR_PORT = int(os.environ.get("TOR_PORT", "9050"))
XRAY_PORT = int(os.environ.get("XRAY_PORT", "1080"))
SITE_LIST = os.environ.get("SITE_LIST", "/app/docker/configs/top1000.txt")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/app/output_pairs")
START_INDEX = int(os.environ.get("START_INDEX", "0"))
POST_WAIT = 2  # seconds to wait after request for trailing packets


def setup_tor():
    import socks
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, TOR_HOST, TOR_PORT)
    socket.socket = socks.socksocket
    socket.getaddrinfo = lambda *a: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a[0], a[1]))]
    return True


def sanitize(name):
    for ch in '<>:"/\\|?*': name = name.replace(ch, "_")
    return name[:200]


def load_sites(path, start=0):
    sites = []
    with open(path, "r", encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) >= 2:
                try: sites.append((int(row[0].strip()), row[1].strip()))
                except: pass
    return sites[start:]


def start_tcpdump(iface, pcap_path, extra_filter=""):
    filt = "tcp" + (f" and {extra_filter}" if extra_filter else "")
    return subprocess.Popen(
        ["tcpdump", "-i", iface, "-w", pcap_path, "-s", "0", "-U", "-n", filt],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


def stop_tcpdump(proc):
    for sig in [signal.SIGTERM, signal.SIGKILL]:
        try: os.kill(proc.pid, sig); time.sleep(0.3)
        except: break
    try: proc.wait(timeout=3)
    except: pass


def clean_small_pcap(path, min_size=60):
    if os.path.exists(path) and os.path.getsize(path) < min_size:
        os.remove(path)
        return 0
    return os.path.getsize(path) if os.path.exists(path) else 0


def capture_pair(url, pre_path, post_path, timeout=REQUEST_TIMEOUT):
    result = {"success": False, "pre_size": 0, "post_size": 0, "http_status": None, "error": None}

    for p in [pre_path, post_path]:
        Path(os.path.dirname(p)).mkdir(parents=True, exist_ok=True)
        if os.path.exists(p): os.remove(p)

    # Start both tcpdumps simultaneously
    pre_proc = start_tcpdump("lo", pre_path, f"port {XRAY_PORT}")
    post_proc = start_tcpdump("eth0", post_path, "")
    time.sleep(0.5)

    try:
        resp = urlopen(url, timeout=timeout)
        result["http_status"] = resp.status
        resp.read(); resp.close()
        result["success"] = True
    except Exception as e:
        result["error"] = str(e)[:80]

    time.sleep(POST_WAIT)

    # Stop both
    stop_tcpdump(pre_proc)
    stop_tcpdump(post_proc)

    result["pre_size"] = clean_small_pcap(pre_path)
    result["post_size"] = clean_small_pcap(post_path)
    return result


def main() -> None:
    print(f"{'='*60}")
    print(f"ToP Dual Capture (pre + post proxy)")
    print(f"  Protocol:   {PROTOCOL}")
    print(f"  Tor:        {TOR_HOST}:{TOR_PORT}")
    print(f"  Xray:       127.0.0.1:{XRAY_PORT}")
    print(f"  Target:     {TARGET_TOTAL} pairs")
    print(f"  Output:     {OUTPUT_DIR}/{PROTOCOL}/")
    print(f"{'='*60}")

    # Wait for Tor FIRST with raw socket (before monkey-patch)
    import socket as raw_socket
    for i in range(30):
        try:
            s = raw_socket.create_connection((TOR_HOST, TOR_PORT), timeout=3)
            s.close()
            print(f"[init] Tor ready")
            break
        except:
            if i % 5 == 0: print(f"  waiting for Tor...")
            time.sleep(2)
    else:
        print("[init] ERROR: Tor not reachable!"); sys.exit(1)

    setup_tor()

    sites = load_sites(SITE_LIST, START_INDEX)
    total, attempts = 0, 0
    target_reached = False
    base = os.path.join(OUTPUT_DIR, PROTOCOL)

    for idx, (rank, domain) in enumerate(sites):
        sd = sanitize(domain)
        site_dir = os.path.join(base, sd)
        Path(site_dir).mkdir(parents=True, exist_ok=True)

        ex = len([f for f in os.listdir(site_dir) if f.endswith("_post.pcap")]) if os.path.isdir(site_dir) else 0
        if ex >= MAX_PCAPS:
            continue

        for pi in range(ex, MAX_PCAPS):
            pre = os.path.join(site_dir, f"{pi+1:03d}_pre.pcap")
            post = os.path.join(site_dir, f"{pi+1:03d}_post.pcap")
            r = capture_pair(f"https://{domain}", pre, post)
            attempts += 1

            if r["success"] and r["pre_size"] > 0 and r["post_size"] > 0:
                total += 1
                st = f"HTTP {r['http_status']}"
                if TARGET_TOTAL > 0 and total >= TARGET_TOTAL:
                    target_reached = True
            else:
                st = f"FAIL: {r.get('error','?')}"

            print(f"[{idx+1:4d}/{len(sites)}] {domain:40s} #{pi+1:02d}  {st:20s}  pre:{r['pre_size']:>5d}B  post:{r['post_size']:>5d}B")

            if target_reached:
                break
            time.sleep(0.5)

        if target_reached:
            break
        if (idx+1) % 50 == 0:
            print(f"--- {total}/{attempts} pairs ({idx+1}/{len(sites)} sites) ---")

    print(f"Complete: {total} pairs -> {base}/")


if __name__ == "__main__":
    main()
