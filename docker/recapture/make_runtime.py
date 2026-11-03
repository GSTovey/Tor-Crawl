#!/usr/bin/env python3
"""Select working nodes and generate mihomo configs for the capture jobs.

Pure mode uses the best working nodes of each protocol.  ToP/Pairs are only
enabled when tor_tests found a Tor-capable node; currently none are available.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PROTOCOLS = ["vless", "ss", "trojan", "anytls", "hysteria2", "mieru"]


def port_ranges(node: dict) -> list[list[int]]:
    out: list[list[int]] = []
    port = int(node.get("port", 0) or 0)
    if 0 < port < 65536:
        out.append([port, port])
    ports = node.get("ports")
    if isinstance(ports, str):
        for chunk in ports.split(","):
            chunk = chunk.strip()
            m = re.match(r"^(\d+)(?:-(\d+))?$", chunk)
            if not m:
                continue
            a = int(m.group(1))
            b = int(m.group(2) or a)
            out.append([min(a, b), max(a, b)])
    elif isinstance(ports, list):
        for chunk in ports:
            try:
                a = int(chunk)
                out.append([a, a])
            except Exception:
                pass
    # Deduplicate / merge only exact duplicates; keep ranges explicit.
    seen = set()
    uniq = []
    for r in out:
        key = (r[0], r[1])
        if key not in seen:
            seen.add(key)
            uniq.append(r)
    return uniq


def write_mihomo(path: Path, nodes: list[dict]) -> None:
    cfg = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "external-controller": "127.0.0.1:9091",
        "secret": "",
        "unified-delay": True,
        "dns": {
            "enable": True,
            "ipv6": False,
            "default-nameserver": ["223.5.5.5"],
            "nameserver": ["223.5.5.5", "119.29.29.29"],
        },
        "proxies": nodes,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": [n["_id"] for n in nodes]}
        ],
        "rules": ["MATCH,PROXY"],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")


def load_working(preflight: Path, proto: str, top: int) -> list[dict]:
    nt_path = preflight / "node_tests" / f"{proto}.json"
    if not nt_path.is_file():
        return []
    nt = json.loads(nt_path.read_text(encoding="utf-8"))
    ok = [r for r in nt.get("results", []) if r.get("ok")]
    ok.sort(key=lambda r: r.get("delay_ms") or 10**9)
    return ok[:top]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--preflight",
        default=str(Path(__file__).resolve().parents[2] / "2026-10-28_Recapture" / "_preflight"),
    )
    ap.add_argument(
        "--runtime",
        default=str(Path(__file__).resolve().parent / "runtime"),
    )
    ap.add_argument("--top-pure", type=int, default=8)
    ap.add_argument("--top-tor", type=int, default=5)
    args = ap.parse_args()

    preflight = Path(args.preflight)
    runtime = Path(args.runtime)
    runtime.mkdir(parents=True, exist_ok=True)

    tor_summary_path = preflight / "tor_tests_summary.json"
    tor_summary = {}
    if tor_summary_path.is_file():
        tor_summary = json.loads(tor_summary_path.read_text(encoding="utf-8"))

    selection: dict = {
        "generated_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%S%z"),
        "protocols": {},
        "missing_protocols": [],
        "tor_missing_protocols": [],
    }

    for proto in PROTOCOLS:
        nodes_path = preflight / "nodes_by_protocol" / f"{proto}.json"
        nodes = (
            json.loads(nodes_path.read_text(encoding="utf-8"))
            if nodes_path.is_file()
            else []
        )
        by_id = {n["_id"]: n for n in nodes}
        working = load_working(preflight, proto, args.top_pure)
        pure_nodes = [dict(by_id[r["id"]]) for r in working if r["id"] in by_id]
        if pure_nodes:
            write_mihomo(runtime / f"pure-{proto}" / "mihomo.json", pure_nodes)
            ports: list[list[int]] = []
            for n in pure_nodes:
                ports.extend(port_ranges(n))
            meta = {
                "job": f"pure-{proto}",
                "mode": "pure",
                "protocol": proto,
                "node_ids": [n["_id"] for n in pure_nodes],
                "allowed_ports": ports,
                "allowed_udp": proto == "hysteria2",
                "nodes": [
                    {
                        "id": n["_id"],
                        "server": n.get("server"),
                        "port": n.get("port"),
                        "ports": n.get("ports"),
                        "source": n.get("_source"),
                        "name": n.get("_orig_name"),
                    }
                    for n in pure_nodes
                ],
            }
            (runtime / f"pure-{proto}" / "meta.json").write_text(
                json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        else:
            selection["missing_protocols"].append(proto)

        # ToP/Pairs: only if Tor bootstrap tests selected nodes.
        tor_ids = (
            tor_summary.get("protocols", {}).get(proto, {}).get("selected", [])
            if tor_summary
            else []
        )
        tor_nodes = [dict(by_id[i]) for i in tor_ids[: args.top_tor] if i in by_id]
        if tor_nodes:
            for mode in ("top", "pairs"):
                write_mihomo(runtime / f"{mode}-{proto}" / "mihomo.json", tor_nodes)
                ports = []
                for n in tor_nodes:
                    ports.extend(port_ranges(n))
                meta = {
                    "job": f"{mode}-{proto}",
                    "mode": mode,
                    "protocol": proto,
                    "node_ids": [n["_id"] for n in tor_nodes],
                    "allowed_ports": ports,
                    "allowed_udp": proto == "hysteria2",
                    "nodes": [
                        {"id": n["_id"], "server": n.get("server"), "port": n.get("port")}
                        for n in tor_nodes
                    ],
                }
                (runtime / f"{mode}-{proto}" / "meta.json").write_text(
                    json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
                )
        elif proto not in ("ss", "mieru"):
            selection["tor_missing_protocols"].append(proto)

        selection["protocols"][proto] = {
            "pure": [n["_id"] for n in pure_nodes],
            "tor": tor_ids,
            "working_total": len(working),
        }

    (preflight / "selected_nodes.json").write_text(
        json.dumps(selection, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(selection, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
