#!/usr/bin/env python3
"""Host-side orchestrator: test Tor bootstrap through top nodes per protocol.

For each protocol, take the best working nodes from node_tests/<p>.json, write a
single-node mihomo config, run recapture:latest tor_test.py in a container, and
record which nodes can actually carry Tor.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

PROTOCOLS = ["vless", "anytls", "hysteria2", "trojan", "ss", "mieru"]


def docker(*args: str, timeout: int | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def make_config(node: dict, path: Path) -> None:
    cfg = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9091",
        "secret": "",
        "unified-delay": True,
        "dns": {
            "enable": True,
            "ipv6": False,
            "default-nameserver": ["223.5.5.5"],
            "nameserver": ["223.5.5.5", "119.29.29.29"],
        },
        "proxies": [node],
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": [node["_id"]]}
        ],
        "rules": ["MATCH,PROXY"],
    }
    path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")


def run_one(
    preflight: Path,
    protocol: str,
    node: dict,
    image: str,
    timeout_s: int,
) -> dict:
    cfg_dir = (preflight / "tor_tests" / "configs").resolve()
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg_name = f"{protocol}-{node['_id']}.json"
    make_config(node, cfg_dir / cfg_name)
    name = f"rc-tortest-{protocol}-{node['_id']}"
    docker("rm", "-f", name)
    started = time.time()
    try:
        proc = docker(
            "run",
            "--rm",
            "--name",
            name,
            "-v",
            f"{cfg_dir}:/cfg:ro",
            "--entrypoint",
            "python",
            image,
            "/app/recapture/tor_test.py",
            "--mihomo-config",
            f"/cfg/{cfg_name}",
            "--protocol",
            protocol,
            "--node-id",
            node["_id"],
            timeout=timeout_s,
        )
        elapsed = round(time.time() - started, 1)
        stdout = (proc.stdout or "").strip()
        try:
            result = json.loads(stdout.splitlines()[-1])
        except Exception:
            result = {
                "success": False,
                "error": f"bad_output rc={proc.returncode}",
                "stdout": stdout[-1500:],
                "stderr": (proc.stderr or "")[-1500:],
            }
        result.update(
            {
                "node_id": node["_id"],
                "name": node.get("_orig_name", ""),
                "server": node.get("server"),
                "port": node.get("port"),
                "type": node.get("type"),
                "delay_ms": node.get("_delay_ms"),
                "elapsed_s": elapsed,
            }
        )
        return result
    except subprocess.TimeoutExpired:
        docker("rm", "-f", name)
        return {
            "node_id": node["_id"],
            "success": False,
            "error": f"host_timeout_{timeout_s}s",
            "elapsed_s": round(time.time() - started, 1),
        }
    finally:
        docker("rm", "-f", name)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--preflight",
        default=str(Path(__file__).resolve().parents[2] / "2026-10-28_Recapture" / "_preflight"),
    )
    ap.add_argument("--image", default="recapture:latest")
    ap.add_argument("--protocols", default="vless,anytls,hysteria2,trojan")
    ap.add_argument("--top", type=int, default=6)
    ap.add_argument("--parallel", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=240)
    args = ap.parse_args()

    preflight = Path(args.preflight)
    protocols = [p.strip() for p in args.protocols.split(",") if p.strip()]
    summary: dict[str, Any] = {"protocols": {}, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}

    for proto in protocols:
        nt_path = preflight / "node_tests" / f"{proto}.json"
        if not nt_path.is_file():
            print(f"[{proto}] no node test results, skip")
            summary["protocols"][proto] = {"selected": [], "tested": 0, "missing": True}
            continue
        nt = json.loads(nt_path.read_text(encoding="utf-8"))
        ok = [r for r in nt.get("results", []) if r.get("ok")]
        ok.sort(key=lambda r: r.get("delay_ms") or 10**9)
        candidates = ok[: args.top]
        if not candidates:
            print(f"[{proto}] no working nodes, skip")
            summary["protocols"][proto] = {"selected": [], "tested": 0, "missing": True}
            continue

        # Full node dicts (for config generation).
        nodes = json.loads(
            (preflight / "nodes_by_protocol" / f"{proto}.json").read_text(encoding="utf-8")
        )
        by_id = {n["_id"]: n for n in nodes}
        chosen: list[dict] = []
        for r in candidates:
            node = dict(by_id.get(r["id"], {}))
            if not node:
                continue
            node["_delay_ms"] = r.get("delay_ms")
            chosen.append(node)

        print(f"\n=== {proto}: testing {len(chosen)} candidates for Tor ===", flush=True)
        results: list[dict] = []
        with ThreadPoolExecutor(max_workers=args.parallel) as pool:
            futs = {
                pool.submit(run_one, preflight, proto, n, args.image, args.timeout): n
                for n in chosen
            }
            for fut in as_completed(futs):
                res = fut.result()
                results.append(res)
                print(
                    f"  {res.get('node_id')}: success={res.get('success')} "
                    f"pct={res.get('bootstrap_pct')} err={res.get('error')}",
                    flush=True,
                )

        results.sort(key=lambda r: (not r.get("success"), r.get("elapsed_s") or 10**9))
        selected_ids = [r["node_id"] for r in results if r.get("success")]
        out_dir = preflight / "tor_tests"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{proto}.json").write_text(
            json.dumps(
                {
                    "protocol": proto,
                    "tested": len(results),
                    "success": len(selected_ids),
                    "selected_ids": selected_ids,
                    "results": results,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        summary["protocols"][proto] = {
            "selected": selected_ids,
            "tested": len(results),
            "success": len(selected_ids),
            "missing": not selected_ids,
        }
        print(
            f"[{proto}] Tor-capable: {len(selected_ids)}/{len(results)} -> {selected_ids}",
            flush=True,
        )

    (preflight / "tor_tests_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
