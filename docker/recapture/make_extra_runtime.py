#!/usr/bin/env python3
"""Create runtime configs for self-hosted SS/VMess ToP/Pairs."""
import json
from pathlib import Path

BASE = {
    "mixed-port": 7890,
    "allow-lan": False,
    "mode": "rule",
    "log-level": "warning",
    "external-controller": "127.0.0.1:9091",
    "secret": "",
    "unified-delay": True,
    "dns": {"enable": False},
}
PROXIES = {
    "ss": {
        "name": "self-ss",
        "type": "ss",
        "server": "172.31.0.10",
        "port": 8388,
        "cipher": "aes-256-gcm",
        "password": "recapture-ss-pass",
        "udp": True,
    },
    "vmess": {
        "name": "self-vmess",
        "type": "vmess",
        "server": "172.31.0.10",
        "port": 8445,
        "uuid": "11111111-1111-4111-8111-111111111111",
        "alterId": 0,
        "cipher": "auto",
        "udp": True,
    },
}

for proto, node in PROXIES.items():
    port = node["port"]
    for mode in ("top", "pairs"):
        job = f"{mode}-{proto}-local"
        d = Path("docker/recapture/runtime") / job
        d.mkdir(parents=True, exist_ok=True)
        cfg = dict(BASE)
        cfg["proxies"] = [node]
        cfg["proxy-groups"] = [
            {"name": "PROXY", "type": "select", "proxies": [node["name"]]}
        ]
        cfg["rules"] = ["MATCH,PROXY"]
        (d / "mihomo.json").write_text(
            json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        meta = {
            "job": job,
            "mode": mode,
            "protocol": proto,
            "node_ids": [node["name"]],
            "allowed_ports": [[port, port]],
            "allowed_endpoints": [["172.31.0.10", port]],
            "allowed_udp": False,
            "selfhost": True,
            "nodes": [{"id": node["name"], "server": "172.31.0.10", "port": port}],
        }
        (d / "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(job)
