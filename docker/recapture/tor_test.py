#!/usr/bin/env python3
"""Test whether Tor can bootstrap through one mihomo proxy node.

Runs inside the recapture container:
  mihomo (single node) -> Tor (Socks5Proxy 127.0.0.1:7890) -> check.torproject.org

Prints one JSON object to stdout.  Used by tor_test_all.py on the host.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen


def _wait_port(host: str, port: int, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.close()
            return True
        except Exception:
            time.sleep(0.3)
    return False


def _tail(path: Path, n: int = 30) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(lines[-n:])
    except Exception:
        return ""


def _bootstrap_state(log_path: Path) -> tuple[int, str]:
    """Return (percent, last bootstrap line)."""
    pct = 0
    last = ""
    try:
        for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "Bootstrapped " in line:
                last = line
                try:
                    part = line.split("Bootstrapped ", 1)[1].split("%", 1)[0]
                    pct = max(pct, int(part.strip()))
                except Exception:
                    pass
    except Exception:
        pass
    return pct, last


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mihomo-config", required=True)
    ap.add_argument("--protocol", default="unknown")
    ap.add_argument("--node-id", default="unknown")
    ap.add_argument("--bootstrap-timeout", type=int, default=120)
    ap.add_argument("--request-timeout", type=int, default=25)
    ap.add_argument(
        "--bridges-file",
        default="",
        help="optional file with 'Bridge ...' lines (obfs4/webtunnel)",
    )
    args = ap.parse_args()

    work = Path(f"/tmp/tortest-{args.node_id}")
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    (work / "mihomo").mkdir(exist_ok=True)
    (work / "tor-data").mkdir(exist_ok=True)

    mihomo_log = work / "mihomo.log"
    tor_log = work / "tor-data" / "log"
    torrc = work / "torrc"
    rc_lines = [
        "SocksPort 127.0.0.1:9050",
        "Socks5Proxy 127.0.0.1:7890",
        f"DataDirectory {work / 'tor-data'}",
        f"Log notice file {tor_log}",
        "AvoidDiskWrites 1",
        "ClientOnly 1",
    ]
    bridge_lines: list[str] = []
    if args.bridges_file:
        try:
            for line in Path(args.bridges_file).read_text(
                encoding="utf-8", errors="replace"
            ).splitlines():
                line = line.strip()
                if line.startswith("Bridge "):
                    bridge_lines.append(line)
        except Exception:
            bridge_lines = []
    if bridge_lines:
        rc_lines.append("UseBridges 1")
        joined = " ".join(bridge_lines)
        if "obfs4" in joined:
            rc_lines.append("ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy")
        if "webtunnel" in joined:
            rc_lines.append(
                "ClientTransportPlugin webtunnel exec /usr/bin/webtunnel-client"
            )
        rc_lines.extend(bridge_lines)
    torrc.write_text("\n".join(rc_lines) + "\n", encoding="utf-8")

    mihomo_proc = None
    tor_proc = None
    result = {
        "protocol": args.protocol,
        "node_id": args.node_id,
        "success": False,
        "bootstrap_pct": 0,
        "bootstrap_s": None,
        "istor": None,
        "http_204": None,
        "example_status": None,
        "error": None,
        "tor_log_tail": "",
        "mihomo_log_tail": "",
    }
    try:
        with mihomo_log.open("w", encoding="utf-8") as mlog:
            mihomo_proc = subprocess.Popen(
                [
                    "mihomo",
                    "-d",
                    str(work / "mihomo"),
                    "-f",
                    args.mihomo_config,
                ],
                stdout=mlog,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        if not _wait_port("127.0.0.1", 7890, 20):
            result["error"] = "mihomo_not_ready"
            return 0

        with tor_log.open("w", encoding="utf-8") as tlog:
            tor_proc = subprocess.Popen(
                ["tor", "-f", str(torrc)],
                stdout=tlog,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

        started = time.time()
        ready = False
        while time.time() - started < args.bootstrap_timeout:
            pct, _ = _bootstrap_state(tor_log)
            result["bootstrap_pct"] = pct
            if pct >= 100:
                ready = True
                result["bootstrap_s"] = round(time.time() - started, 1)
                break
            if pct >= 75 and _wait_port("127.0.0.1", 9050, 2):
                # 75% is enough to build circuits; try a real request below.
                result["bootstrap_s"] = round(time.time() - started, 1)
                ready = True
                break
            if tor_proc.poll() is not None:
                result["error"] = f"tor_exited_{tor_proc.returncode}"
                break
            time.sleep(1)

        if not ready:
            if not result["error"]:
                result["error"] = "bootstrap_timeout"
            result["tor_log_tail"] = _tail(tor_log)
            result["mihomo_log_tail"] = _tail(mihomo_log)
            return 0

        # Route Python's sockets through Tor.
        import socks

        original_socket = socket.socket
        original_getaddrinfo = socket.getaddrinfo
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
        socket.socket = socks.socksocket
        socket.getaddrinfo = lambda *a, **kw: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (a[0], a[1]))
        ]
        try:
            try:
                with urlopen(
                    "https://check.torproject.org/api/ip",
                    timeout=args.request_timeout,
                ) as r:
                    body = json.loads(r.read().decode("utf-8", "replace"))
                    result["istor"] = bool(body.get("IsTor"))
            except Exception as exc:
                result["istor"] = f"error:{str(exc)[:120]}"

            try:
                with urlopen(
                    "http://cp.cloudflare.com/generate_204",
                    timeout=args.request_timeout,
                ) as r:
                    result["http_204"] = r.status
            except Exception as exc:
                result["http_204"] = f"error:{str(exc)[:120]}"

            try:
                with urlopen(
                    "https://example.com", timeout=args.request_timeout
                ) as r:
                    result["example_status"] = r.status
                    r.read(1024)
            except Exception as exc:
                result["example_status"] = f"error:{str(exc)[:120]}"
        finally:
            socket.socket = original_socket
            socket.getaddrinfo = original_getaddrinfo

        requests_ok = (
            result["http_204"] == 204
            or result["example_status"] == 200
            or result["istor"] is True
        )
        result["success"] = requests_ok
        if not requests_ok:
            result["error"] = "tor_requests_failed"
        return 0
    finally:
        for proc in (tor_proc, mihomo_proc):
            if proc is not None and proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except Exception:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
        time.sleep(0.5)
        for proc in (tor_proc, mihomo_proc):
            if proc is not None and proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    pass
        result["tor_log_tail"] = _tail(tor_log)
        result["mihomo_log_tail"] = _tail(mihomo_log)
        print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())
