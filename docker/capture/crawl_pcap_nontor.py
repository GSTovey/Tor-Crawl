#!/usr/bin/env python3
"""NonTor direct capture — no proxy, no Tor, raw HTTP + tcpdump."""
import os, sys, time, signal, subprocess, csv
from pathlib import Path
from urllib.request import urlopen

PROTOCOL = os.environ.get("PROTOCOL", "NonTor")
MAX_PCAPS = int(os.environ.get("MAX_PCAPS", "10"))
TARGET_TOTAL = int(os.environ.get("TARGET_TOTAL", "10000"))
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "30"))
SITE_LIST = os.environ.get("SITE_LIST", "/app/docker/configs/top1000.txt")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/app/Tor_output")
TCPDUMP_IFACE = os.environ.get("TCPDUMP_IFACE", "eth0")

def sanitize(name):
    for ch in '<>:"/\\|?*': name = name.replace(ch, "_")
    return name[:200]

def load_sites(path):
    sites = []
    with open(path, "r", encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) >= 2:
                try: sites.append((int(row[0].strip()), row[1].strip()))
                except: pass
    return sites

def capture_one(url, pcap_path, timeout=REQUEST_TIMEOUT):
    result = {"success": False, "pcap_size": 0, "http_status": None, "error": None}
    Path(os.path.dirname(pcap_path)).mkdir(parents=True, exist_ok=True)
    if os.path.exists(pcap_path): os.remove(pcap_path)
    tcpdump = subprocess.Popen(["tcpdump","-i",TCPDUMP_IFACE,"-w",pcap_path,"-s","0","-U","-n","tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    try:
        resp = urlopen(f"https://{url}", timeout=timeout)
        result["http_status"] = resp.status
        resp.read(); resp.close()
        result["success"] = True
    except Exception as e:
        result["error"] = str(e)[:80]
    time.sleep(2)
    for sig in [signal.SIGTERM, signal.SIGKILL]:
        try: os.kill(tcpdump.pid, sig); time.sleep(0.3)
        except: break
    tcpdump.wait(timeout=3)
    if os.path.exists(pcap_path):
        result["pcap_size"] = os.path.getsize(pcap_path)
        if result["pcap_size"] < 60: os.remove(pcap_path); result["pcap_size"] = 0
    return result

def main():
    print(f"=== NonTor Direct Capture ===")
    sites = load_sites(SITE_LIST)
    total, target_reached = 0, False
    base = os.path.join(OUTPUT_DIR, PROTOCOL)
    for idx, (rank, domain) in enumerate(sites):
        sd = sanitize(domain); Path(os.path.join(base, sd)).mkdir(parents=True, exist_ok=True)
        ex = len([f for f in os.listdir(os.path.join(base, sd)) if f.endswith(".pcap")]) if os.path.isdir(os.path.join(base, sd)) else 0
        if ex >= MAX_PCAPS: continue
        for pi in range(ex, MAX_PCAPS):
            r = capture_one(domain, os.path.join(base, sd, f"{pi+1:03d}.pcap"))
            if r["success"] and r["pcap_size"] > 0:
                total += 1
                if TARGET_TOTAL > 0 and total >= TARGET_TOTAL: target_reached = True; break
            print(f"[{idx+1:4d}] {domain:40s} #{pi+1:02d} {'HTTP '+str(r['http_status']) if r['success'] else 'FAIL'}")
            time.sleep(0.3)
        if target_reached: break
    print(f"Done: {total} PCAPs -> {base}/")

if __name__ == "__main__": main()
