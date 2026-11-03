#!/usr/bin/env python3
"""End-to-end node test using a temporary mihomo container.

For each protocol:
  1. start metacubex/mihomo with the generated test config
  2. call the controller's per-proxy delay endpoint for every node
  3. record success/latency and stop the container

This tests the actual proxy handshake and an HTTP request through the node,
not just TCP reachability.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import urlopen

PROTOCOLS = ["vless", "ss", "trojan", "anytls", "hysteria2", "mieru"]
TEST_URLS = [
    "http://cp.cloudflare.com/generate_204",
    "http://www.gstatic.com/generate_204",
    "https://www.gstatic.com/generate_204",
    "https://www.baidu.com",
]


def docker(*args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    cmd = ["docker", *args]
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def wait_controller(port: int, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urlopen(f"http://127.0.0.1:{port}/version", timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def probe(port: int, name: str, url: str, timeout_ms: int) -> tuple[bool, int | None, str]:
    api = (
        f"http://127.0.0.1:{port}/proxies/{quote(name, safe='')}/delay"
        f"?url={quote(url, safe='')}&timeout={timeout_ms}"
    )
    try:
        with urlopen(api, timeout=timeout_ms / 1000.0 + 6.0) as r:
            body = r.read().decode("utf-8", "replace")
        data = json.loads(body)
        delay = data.get("delay")
        if isinstance(delay, int) and delay > 0:
            return True, delay, ""
        return False, None, f"bad_response:{body[:120]}"
    except HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return False, None, f"http_{exc.code}:{body[:120]}"
    except Exception as exc:
        return False, None, str(exc)[:160]


def test_node(port: int, node: dict, timeout_ms: int) -> dict:
    name = node["_id"]
    attempts: list[dict] = []
    for url in TEST_URLS:
        ok, delay, err = probe(port, name, url, timeout_ms)
        attempts.append({"url": url, "ok": ok, "delay": delay, "error": err})
        if ok:
            return {
                "id": name,
                "name": node.get("_orig_name", ""),
                "type": node.get("type"),
                "server": node.get("server"),
                "port": node.get("port"),
                "source": node.get("_source"),
                "source_file": node.get("_source_file"),
                "ok": True,
                "delay_ms": delay,
                "test_url": url,
                "attempts": attempts,
            }
    return {
        "id": name,
        "name": node.get("_orig_name", ""),
        "type": node.get("type"),
        "server": node.get("server"),
        "port": node.get("port"),
        "source": node.get("_source"),
        "source_file": node.get("_source_file"),
        "ok": False,
        "delay_ms": None,
        "test_url": None,
        "attempts": attempts,
    }


def one_protocol(
    preflight: Path,
    proto: str,
    image: str,
    host_port: int,
    workers: int,
    timeout_ms: int,
) -> dict:
    nodes_path = preflight / "nodes_by_protocol" / f"{proto}.json"
    cfg_path = preflight / "test_configs" / f"{proto}.json"
    nodes = json.loads(nodes_path.read_text(encoding="utf-8"))
    if not nodes:
        return {"protocol": proto, "total": 0, "ok": 0, "results": []}

    name = f"recapture-nodetest-{proto}"
    docker("rm", "-f", name, check=False)
    cfg_dir = cfg_path.parent.resolve()
    run = docker(
        "run",
        "-d",
        "--name",
        name,
        "-p",
        f"127.0.0.1:{host_port}:19090",
        "-v",
        f"{cfg_dir}:/cfg:ro",
        "--entrypoint",
        "/mihomo",
        image,
        "-d",
        "/tmp/mihomo",
        "-f",
        f"/cfg/{proto}.json",
        check=False,
    )
    if run.returncode != 0:
        return {
            "protocol": proto,
            "total": len(nodes),
            "ok": 0,
            "error": f"container_start_failed: {run.stderr[:500]}",
            "results": [],
        }

    try:
        if not wait_controller(host_port):
            logs = docker("logs", "--tail", "30", name, check=False).stdout
            return {
                "protocol": proto,
                "total": len(nodes),
                "ok": 0,
                "error": f"controller_not_ready; logs={logs[:1500]}",
                "results": [],
            }

        results: list[dict] = []
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(test_node, host_port, n, timeout_ms): n for n in nodes
            }
            for i, fut in enumerate(as_completed(futures), 1):
                try:
                    results.append(fut.result())
                except Exception as exc:
                    n = futures[fut]
                    results.append(
                        {
                            "id": n["_id"],
                            "name": n.get("_orig_name", ""),
                            "type": n.get("type"),
                            "server": n.get("server"),
                            "port": n.get("port"),
                            "source": n.get("_source"),
                            "ok": False,
                            "delay_ms": None,
                            "test_url": None,
                            "attempts": [],
                            "error": str(exc)[:160],
                        }
                    )
                if i % 25 == 0:
                    ok_so_far = sum(1 for r in results if r["ok"])
                    print(
                        f"  [{proto}] {i}/{len(nodes)} tested, {ok_so_far} ok, "
                        f"{time.time()-t0:.0f}s",
                        flush=True,
                    )

        results.sort(key=lambda r: (not r["ok"], r["delay_ms"] or 10**9))
        ok_results = [r for r in results if r["ok"]]
        delays = [r["delay_ms"] for r in ok_results if r["delay_ms"]]
        summary = {
            "protocol": proto,
            "total": len(nodes),
            "ok": len(ok_results),
            "https_ok": sum(
                1 for r in ok_results if (r.get("test_url") or "").startswith("https")
            ),
            "median_delay_ms": int(statistics.median(delays)) if delays else None,
            "min_delay_ms": min(delays) if delays else None,
            "elapsed_s": round(time.time() - t0, 1),
            "top": [
                {
                    "id": r["id"],
                    "name": r["name"],
                    "delay_ms": r["delay_ms"],
                    "url": r["test_url"],
                    "source": r["source"],
                }
                for r in ok_results[:15]
            ],
            "results": results,
        }
        out_dir = preflight / "node_tests"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{proto}.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return summary
    finally:
        docker("rm", "-f", name, check=False)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--preflight",
        default=str(Path(__file__).resolve().parents[2] / "2026-10-28_Recapture" / "_preflight"),
    )
    ap.add_argument("--image", default="metacubex/mihomo:latest")
    ap.add_argument("--protocols", default=",".join(PROTOCOLS))
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--timeout-ms", type=int, default=5000)
    ap.add_argument("--base-port", type=int, default=19190)
    args = ap.parse_args()

    preflight = Path(args.preflight)
    protocols = [p.strip() for p in args.protocols.split(",") if p.strip()]
    summaries = []
    for idx, proto in enumerate(protocols):
        print(f"\n=== {proto} ===", flush=True)
        summary = one_protocol(
            preflight,
            proto,
            args.image,
            args.base_port + idx,
            args.workers,
            args.timeout_ms,
        )
        summaries.append({k: v for k, v in summary.items() if k != "results"})
        print(json.dumps(summaries[-1], ensure_ascii=False, indent=2), flush=True)

    out = preflight / "node_tests_summary.json"
    out.write_text(
        json.dumps(
            {"protocols": summaries, "test_urls": TEST_URLS}, ensure_ascii=False, indent=2
        ),
        encoding="utf-8",
    )
    print(f"\n[ok] summary -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
