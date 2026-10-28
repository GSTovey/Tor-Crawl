"""Fetch Clash subscription and split by protocol type."""
import yaml, json, sys, os, re
from urllib.request import urlopen, Request
from collections import Counter

URL = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("CLASH_SUB_URL", "")

# Fetch with multiple attempts
for ua in ["clash-verge/2.0.0", "ClashMeta/1.18.0", "clash", ""]:
    try:
        headers = {"User-Agent": ua, "Accept": "*/*"} if ua else {"Accept": "*/*"}
        data = urlopen(Request(URL, headers=headers), timeout=30).read()
        text = data.decode("utf-8", errors="replace")
        print(f"UA={ua[:25]}: {len(data)} bytes")
        if len(data) > 1000:
            break
    except Exception as e:
        print(f"UA={ua[:25]}: {e}")

# Parse YAML
cfg = yaml.safe_load(text)
proxies = cfg.get("proxies", [])
print(f"Total proxies: {len(proxies)}")

# Count by type
types = Counter(p.get("type", "?") for p in proxies)
for t, c in types.most_common():
    print(f"  {t}: {c}")

# Save per-protocol configs
OUT_DIR = "configs/clash"
os.makedirs(OUT_DIR, exist_ok=True)

for proto, nodes in [(t, [p for p in proxies if p.get("type") == t]) for t in types]:
    if proto in ("select", "url-test", "fallback", "load-balance", "?"):
        continue
    if len(nodes) == 0:
        continue

    # Create a minimal Clash config with only this protocol's proxies
    # Use url-test to auto-select fastest working node
    clash_cfg = {
        "mixed-port": 7890,
        "allow-lan": True,
        "ipv6": False,
        "mode": "global",
        "log-level": "info",
        "external-controller": "0.0.0.0:9090",
        "tun": {"enable": False},
        "proxies": nodes,
        "proxy-groups": [{
            "name": "Proxy",
            "type": "url-test",
            "proxies": [n["name"] for n in nodes],
            "url": "https://www.gstatic.com/generate_204",
            "interval": 30,
            "tolerance": 50
        }],
        "rules": ["MATCH,Proxy"]
    }

    path = f"{OUT_DIR}/clash-{proto}.yaml"
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(clash_cfg, f, allow_unicode=True, default_flow_style=False)
    print(f"  -> {path} ({len(nodes)} {proto} nodes)")

print("Done.")
