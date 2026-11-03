#!/usr/bin/env python3
"""Pure proxy PCAP capture — no Tor, direct through Xray/Clash SOCKS5."""
import os, sys, time, signal, socket, subprocess, csv
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

PROTOCOL = os.environ.get("PROTOCOL", "unknown")
MAX_PCAPS = int(os.environ.get("MAX_PCAPS", "10"))
TARGET_TOTAL = int(os.environ.get("TARGET_TOTAL", "10000"))
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "30"))
PROXY_HOST = os.environ.get("PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "1080"))
SITE_LIST = os.environ.get("SITE_LIST", "/app/docker/configs/top1000.txt")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/app/output")
START_INDEX = int(os.environ.get("START_INDEX", "0"))
TCPDUMP_IFACE = os.environ.get("TCPDUMP_IFACE", "eth0")
TCPDUMP_POST_WAIT = 2

def setup_proxy():
    try:
        import socks
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, PROXY_HOST, PROXY_PORT)
        socket.socket = socks.socksocket
        socket.getaddrinfo = lambda *a: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a[0], a[1]))]
        return True
    except Exception as e:
        print(f"[proxy] ERROR: {e}")
        return False

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
    print(f"[sites] {len(sites)} domains, start={start}")
    return sites[start:]

def capture_one(url, pcap_path, timeout=REQUEST_TIMEOUT):
    result = {"success": False, "pcap_size": 0, "http_status": None, "error": None, "duration": 0.0}
    Path(os.path.dirname(pcap_path)).mkdir(parents=True, exist_ok=True)
    if os.path.exists(pcap_path): os.remove(pcap_path)

    tcpdump = subprocess.Popen(
        ["tcpdump", "-i", TCPDUMP_IFACE, "-w", pcap_path, "-s", "0", "-U", "-n", "tcp"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(0.5)
    t0 = time.monotonic()
    try:
        resp = urlopen(url, timeout=timeout)
        result["http_status"] = resp.status
        resp.read()
        resp.close()
        result["success"] = True
    except Exception as e:
        result["error"] = str(e)[:80]
    result["duration"] = round(time.monotonic() - t0, 2)
    time.sleep(TCPDUMP_POST_WAIT)

    for sig in [signal.SIGTERM, signal.SIGKILL]:
        try: os.kill(tcpdump.pid, sig); time.sleep(0.3)
        except: break
    tcpdump.wait(timeout=3)

    if os.path.exists(pcap_path):
        result["pcap_size"] = os.path.getsize(pcap_path)
        if result["pcap_size"] < 60:
            os.remove(pcap_path)
            result["pcap_size"] = 0
    return result

def main():
    print(f"{'='*60}")
    print(f"Pure Proxy PCAP Capture (NO Tor)")
    print(f"  Protocol:   {PROTOCOL}")
    print(f"  Proxy:      {PROXY_HOST}:{PROXY_PORT}")
    print(f"  Target:     {TARGET_TOTAL} PCAPs")
    print(f"  Max/site:   {MAX_PCAPS}")
    print(f"  Output:     {OUTPUT_DIR}/{PROTOCOL}/")
    print(f"{'='*60}")

    if not setup_proxy():
        sys.exit(1)

    # Verify proxy
    for i in range(10):
        try:
            s = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=3)
            s.close()
            print(f"[init] Proxy ready ({PROXY_HOST}:{PROXY_PORT})")
            break
        except:
            time.sleep(1)
    else:
        print("[init] ERROR: Proxy not reachable!")
        sys.exit(1)

    sites = load_sites(SITE_LIST, START_INDEX)
    total_captured, total_attempts = 0, 0
    target_reached = False
    base_out = os.path.join(OUTPUT_DIR, PROTOCOL)

    for site_idx, (rank, domain) in enumerate(sites):
        safe = sanitize(domain)
        site_dir = os.path.join(base_out, safe)
        Path(site_dir).mkdir(parents=True, exist_ok=True)

        existing = len([f for f in os.listdir(site_dir) if f.endswith(".pcap")]) if os.path.isdir(site_dir) else 0
        if existing >= MAX_PCAPS:
            continue

        for pcap_idx in range(existing, MAX_PCAPS):
            url = f"https://{domain}"
            result = capture_one(url, os.path.join(site_dir, f"{pcap_idx+1:03d}.pcap"))
            total_attempts += 1

            if result["success"] and result["pcap_size"] > 0:
                total_captured += 1
                st = f"HTTP {result['http_status']}"
                if TARGET_TOTAL > 0 and total_captured >= TARGET_TOTAL:
                    print(f"\n{'='*60}\nTarget reached: {total_captured}/{TARGET_TOTAL}. Stopping.\n{'='*60}")
                    target_reached = True
                    break
            else:
                st = f"FAIL: {result.get('error','?')}"

            print(f"[{site_idx+1:4d}/{len(sites)}] {domain:40s} #{pcap_idx+1:02d}  {st:20s}  {result['pcap_size']:>6d}B  {result['duration']:>5.1f}s")
            time.sleep(0.3)

        if target_reached:
            break
        if (site_idx+1) % 50 == 0:
            print(f"--- Progress: {total_captured}/{total_attempts} ({site_idx+1}/{len(sites)} sites) ---")

    print(f"Complete: {total_captured}/{total_attempts} PCAPs -> {base_out}/")

if __name__ == "__main__":
    main()
