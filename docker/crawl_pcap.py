#!/usr/bin/env python3
"""
PCAP Traffic Capture Crawler — visits Tranco Top-N websites through
Tor-over-Proxy and captures each request's encrypted proxy traffic.

Architecture:
  1. Read domain list (Tranco Top 1000)
  2. For each domain, make up to MAX_PCAPS HTTP requests
  3. Per request: start tcpdump → HTTP through Tor SOCKS5 → stop → save PCAP
  4. tcpdump captures on eth0 — sees encrypted Xray protocol traffic

PCAP naming:  output/<protocol>/<domain>/<NNN>.pcap

Usage (inside Docker container):
  python /app/docker/crawl_pcap.py

Environment variables:
  PROTOCOL       - proxy protocol name (ss/trojan/vmess/vless)
  MAX_PCAPS      - max PCAPs per site (default: 10)
  REQUEST_TIMEOUT- HTTP request timeout in seconds (default: 30)
  TOR_HOST       - Tor SOCKS5 host (default: 127.0.0.1)
  TOR_PORT       - Tor SOCKS5 port (default: 9050)
  SITE_LIST      - path to domain list (default: /app/docker/configs/top1000.txt)
  OUTPUT_DIR     - PCAP output root (default: /app/output)
  START_INDEX    - site index to start from (default: 0, for resume)
"""

import csv
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

# ── Configuration from environment ──────────────────────────────────
PROTOCOL = os.environ.get("PROTOCOL", "unknown")
MAX_PCAPS = int(os.environ.get("MAX_PCAPS", "10"))
TARGET_TOTAL = int(os.environ.get("TARGET_TOTAL", "0"))  # 0 = no limit
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "30"))
TOR_HOST = os.environ.get("TOR_HOST", "127.0.0.1")
TOR_PORT = int(os.environ.get("TOR_PORT", "9050"))
SITE_LIST = os.environ.get(
    "SITE_LIST", "/app/docker/configs/top1000.txt"
)
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/app/output")
START_INDEX = int(os.environ.get("START_INDEX", "0"))

# tcpdump settings
TCPDUMP_IFACE = os.environ.get("TCPDUMP_IFACE", "eth0")
TCPDUMP_SNAPLEN = os.environ.get("TCPDUMP_SNAPLEN", "0")   # 0 = full packet
TCPDUMP_POST_WAIT = 2  # seconds to wait after request before stopping tcpdump


# ── Setup Tor SOCKS5 monkey-patch ───────────────────────────────────
def setup_tor_proxy():
    """Route all Python socket traffic through Tor SOCKS5."""
    try:
        import socks
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, TOR_HOST, TOR_PORT)
        socket.socket = socks.socksocket
        socket.getaddrinfo = lambda *args: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (args[0], args[1]))
        ]
        print(f"[tor] SOCKS5 proxy set to {TOR_HOST}:{TOR_PORT}")
        return True
    except ImportError:
        print("[tor] ERROR: pysocks not installed!")
        return False
    except Exception as e:
        print(f"[tor] ERROR: {e}")
        return False


# ── Helpers ─────────────────────────────────────────────────────────
def load_sites(path: str, start: int = 0) -> list[tuple[int, str]]:
    """Load domain list from Tranco CSV (rank,domain)."""
    sites = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                try:
                    rank = int(row[0].strip())
                    domain = row[1].strip()
                    sites.append((rank, domain))
                except ValueError:
                    continue
    print(f"[sites] Loaded {len(sites)} domains, starting at index {start}")
    return sites[start:]


def sanitize_filename(name: str) -> str:
    """Replace filesystem-unsafe characters."""
    unsafe = '<>:"/\\|?*'
    for ch in unsafe:
        name = name.replace(ch, "_")
    return name[:200]  # limit length


def ensure_dir(path: str) -> None:
    """Create directory if it doesn't exist."""
    Path(path).mkdir(parents=True, exist_ok=True)


def tcpdump_running(pid: int) -> bool:
    """Check if tcpdump process is still alive."""
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


# ── Core: capture one request ───────────────────────────────────────
def capture_one_request(
    url: str,
    pcap_path: str,
    timeout: int = REQUEST_TIMEOUT,
) -> dict:
    """
    Make one HTTP request and capture the resulting traffic to a PCAP file.

    Returns:
      dict with keys: success (bool), pcap_size (int), http_status (int|None),
                      error (str|None), duration (float)
    """
    result = {
        "success": False,
        "pcap_size": 0,
        "http_status": None,
        "error": None,
        "duration": 0.0,
    }

    # Ensure output directory
    ensure_dir(os.path.dirname(pcap_path))

    # Remove stale PCAP if exists
    if os.path.exists(pcap_path):
        os.remove(pcap_path)

    # Start tcpdump in background
    tcpdump_cmd = [
        "tcpdump",
        "-i", TCPDUMP_IFACE,
        "-w", pcap_path,
        "-s", TCPDUMP_SNAPLEN,
        "-U",                    # flush each packet
        "-n",                    # don't resolve hostnames
        "tcp",                   # only TCP traffic
    ]
    try:
        tcpdump_proc = subprocess.Popen(
            tcpdump_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        result["error"] = "tcpdump not found"
        return result
    except Exception as e:
        result["error"] = f"tcpdump start failed: {e}"
        return result

    # Give tcpdump a moment to start
    time.sleep(0.5)

    # Make HTTP request through Tor
    t_start = time.monotonic()
    try:
        resp = urlopen(url, timeout=timeout)
        result["http_status"] = resp.status
        _ = resp.read()  # consume body to ensure full capture
        resp.close()
        result["success"] = True
    except URLError as e:
        result["error"] = f"URLError: {e.reason}"
    except socket.timeout:
        result["error"] = "socket timeout"
    except Exception as e:
        result["error"] = f"request error: {e}"

    t_end = time.monotonic()
    result["duration"] = round(t_end - t_start, 2)

    # Wait for trailing packets, then stop tcpdump
    time.sleep(TCPDUMP_POST_WAIT)

    # Graceful stop: SIGTERM first, then SIGKILL if needed
    for sig in [signal.SIGTERM, signal.SIGKILL]:
        if not tcpdump_running(tcpdump_proc.pid):
            break
        try:
            os.kill(tcpdump_proc.pid, sig)
            time.sleep(0.5)
        except OSError:
            break

    tcpdump_proc.wait(timeout=3)

    # Check PCAP file size
    if os.path.exists(pcap_path):
        result["pcap_size"] = os.path.getsize(pcap_path)
    else:
        result["pcap_size"] = 0

    # Remove empty or tiny PCAPs (connection likely failed)
    if result["pcap_size"] < 60:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)
        result["pcap_size"] = 0

    return result


# ── Main loop ───────────────────────────────────────────────────────
def main():
    print(f"{'='*60}")
    print(f"TorCrawl PCAP Capture")
    print(f"  Protocol:   {PROTOCOL}")
    target_msg = f"  Target:     {TARGET_TOTAL} total PCAPs" if TARGET_TOTAL > 0 else "  Target:     unlimited"
    print(f"  Max PCAPs:  {MAX_PCAPS} per site")
    print(target_msg)
    print(f"  Timeout:    {REQUEST_TIMEOUT}s")
    print(f"  Tor:        {TOR_HOST}:{TOR_PORT}")
    print(f"  Interface:  {TCPDUMP_IFACE}")
    print(f"  Output:     {OUTPUT_DIR}/{PROTOCOL}/")
    print(f"{'='*60}")

    # Wait for Tor to be ready FIRST (use raw socket, before monkey-patch)
    print("[init] Waiting for Tor SOCKS5...")
    import socket as _raw_socket
    for i in range(30):
        try:
            s = _raw_socket.create_connection((TOR_HOST, TOR_PORT), timeout=3)
            s.close()
            print(f"[init] Tor ready ({TOR_HOST}:{TOR_PORT})")
            break
        except Exception:
            if i % 5 == 0:
                print(f"  waiting... ({i}s)")
            time.sleep(1)
    else:
        print("[init] ERROR: Tor not reachable!")
        sys.exit(1)

    # Setup Tor proxy (AFTER confirming Tor is reachable)
    if not setup_tor_proxy():
        sys.exit(1)

    # Load site list
    sites = load_sites(SITE_LIST, START_INDEX)
    if not sites:
        print("[init] ERROR: No sites to crawl!")
        sys.exit(1)

    total_captured = 0
    total_attempts = 0
    target_reached = False
    base_out = os.path.join(OUTPUT_DIR, PROTOCOL)

    for site_idx, (rank, domain) in enumerate(sites):
        safe_domain = sanitize_filename(domain)
        site_dir = os.path.join(base_out, safe_domain)
        ensure_dir(site_dir)

        # Count existing PCAPs for this site (for resume)
        existing = 0
        if os.path.isdir(site_dir):
            existing = len([
                f for f in os.listdir(site_dir) if f.endswith(".pcap")
            ])

        if existing >= MAX_PCAPS:
            if site_idx % 100 == 0:
                print(f"[{site_idx+1}/{len(sites)}] {domain} — {existing} PCAPs (skip)")
            continue

        for pcap_idx in range(existing, MAX_PCAPS):
            pcap_name = f"{pcap_idx+1:03d}.pcap"
            pcap_path = os.path.join(site_dir, pcap_name)
            url = f"https://{domain}"

            result = capture_one_request(url, pcap_path)
            total_attempts += 1

            if result["success"] and result["pcap_size"] > 0:
                total_captured += 1
                status = f"HTTP {result['http_status']}"
                # Check target
                if TARGET_TOTAL > 0 and total_captured >= TARGET_TOTAL:
                    print(f"\n{'='*60}")
                    print(f"Target reached: {total_captured}/{TARGET_TOTAL} PCAPs captured. Stopping.")
                    print(f"{'='*60}")
                    target_reached = True
                    break
            else:
                status = f"FAIL: {result.get('error', '?')}"

            print(
                f"[{site_idx+1:4d}/{len(sites)}] {domain:40s} "
                f"#{pcap_idx+1:02d}  {status:20s}  "
                f"{result['pcap_size']:>6d}B  {result['duration']:>5.1f}s"
            )

            # Brief pause between requests to avoid overwhelming Tor
            time.sleep(0.5)

        if target_reached:
            break

        # Progress summary every 50 sites
        if (site_idx + 1) % 50 == 0:
            print(f"--- Progress: {total_captured}/{total_attempts} captured "
                  f"({site_idx+1}/{len(sites)} sites) ---")

    print(f"{'='*60}")
    print(f"Complete: {total_captured}/{total_attempts} PCAPs captured")
    print(f"Output:   {base_out}/")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
