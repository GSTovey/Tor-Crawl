#!/usr/bin/env python3
"""Launch one recapture job container."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--job", required=True, help="e.g. pure-vless / nontor")
    ap.add_argument("--mode", default="")
    ap.add_argument("--protocol", default="")
    ap.add_argument("--base-subdir", default="")
    ap.add_argument("--target", type=int, default=5000)
    ap.add_argument("--max-per-site", type=int, default=5)
    ap.add_argument("--site-list", default=str(ROOT / "docker" / "configs" / "top1000.txt"))
    ap.add_argument("--output", default=str(ROOT / "2026-10-28_Recapture"))
    ap.add_argument("--runtime", default=str(HERE / "runtime"))
    ap.add_argument("--image", default="recapture:latest")
    ap.add_argument(
        "--network",
        default="",
        help="optional docker network (e.g. recapture-servers for self-hosted proxies)",
    )
    ap.add_argument(
        "--torrc",
        default=str(HERE / "torrc.template"),
        help="torrc to mount for top/pairs (use torrc_bridges.template for bridges)",
    )
    ap.add_argument("--name", default="")
    ap.add_argument("--request-timeout", type=int, default=0)
    ap.add_argument("--max-retries", type=int, default=3)
    ap.add_argument("--run-hours", type=float, default=72)
    ap.add_argument("--detach", action="store_true", default=True)
    ap.add_argument("--foreground", dest="detach", action="store_false")
    args = ap.parse_args()

    mode = args.mode or args.job.split("-")[0]
    protocol = args.protocol
    base_subdir = args.base_subdir
    meta = {}
    if mode == "nontor":
        protocol = protocol or "NonTor"
        base_subdir = base_subdir or "Tor_Direct/NonTor"
    else:
        runtime_meta = Path(args.runtime) / args.job / "meta.json"
        if not runtime_meta.is_file():
            print(f"missing runtime meta: {runtime_meta}", file=sys.stderr)
            return 2
        meta = json.loads(runtime_meta.read_text(encoding="utf-8"))
        protocol = protocol or meta["protocol"]
        mode_dir = {
            "pure": "Pure_Proxy",
            "pairs": "Traffic_Pairs",
            "top": "Tor_over_Proxy",
        }.get(mode, mode)
        base_subdir = base_subdir or f"{mode_dir}/{protocol}"

    name = args.name or f"rc-{args.job}"
    out_dir = Path(args.output).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    site_list = Path(args.site_list).resolve()
    if not site_list.is_file():
        print(f"missing site list: {site_list}", file=sys.stderr)
        return 2

    env = {
        "MODE": mode,
        "PROTOCOL": protocol,
        "BASE_SUBDIR": base_subdir,
        "OUTPUT_DIR": "/app/output",
        "TARGET_TOTAL": str(args.target),
        "MAX_PER_SITE": str(args.max_per_site),
        "SITE_LIST": "/app/sites/sites.txt",
        "RUN_HOURS": str(args.run_hours),
        "MAX_RETRIES": str(args.max_retries),
        "SWITCH_AFTER": "8",
        "DISK_MIN_GB": "50",
        "POST_WAIT": "1.2",
        "MAX_BODY": str(256 * 1024),
    }
    if args.request_timeout:
        env["REQUEST_TIMEOUT"] = str(args.request_timeout)
    if mode != "nontor":
        env.update(
            {
                "MIHOMO_CONFIG": "/etc/mihomo/config.yaml",
                "MIHOMO_API": "http://127.0.0.1:9091",
                "NODE_IDS": json.dumps(meta.get("node_ids", [])),
                "ALLOWED_PORTS": json.dumps(meta.get("allowed_ports", [])),
                "ALLOWED_ENDPOINTS": json.dumps(meta.get("allowed_endpoints", [])),
                "ALLOWED_UDP": "1" if meta.get("allowed_udp") else "0",
            }
        )

    cmd = [
        "docker",
        "rm",
        "-f",
        name,
    ]
    subprocess.run(cmd, capture_output=True)

    cmd = [
        "docker",
        "run",
        "-d" if args.detach else "--rm",
        "--name",
        name,
        "--cap-add",
        "NET_ADMIN",
        "--cap-add",
        "NET_RAW",
        "-v",
        f"{out_dir}:/app/output",
        "-v",
        f"{site_list}:/app/sites/sites.txt:ro",
    ]
    if args.network:
        cmd += ["--network", args.network]
    if mode != "nontor":
        mihomo = (Path(args.runtime) / args.job / "mihomo.json").resolve()
        if not mihomo.is_file():
            print(f"missing mihomo config: {mihomo}", file=sys.stderr)
            return 2
        cmd += ["-v", f"{mihomo}:/etc/mihomo/config.yaml:ro"]
    if mode in ("top", "pairs"):
        torrc = Path(args.torrc).resolve()
        if not torrc.is_file():
            print(f"missing torrc: {torrc}", file=sys.stderr)
            return 2
        cmd += ["-v", f"{torrc}:/etc/tor/torrc:ro"]
    for k, v in env.items():
        cmd += ["-e", f"{k}={v}"]
    cmd += [args.image]

    print(" ".join(cmd))
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        return proc.returncode
    print(proc.stdout.strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
