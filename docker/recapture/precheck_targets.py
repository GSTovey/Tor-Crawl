#!/usr/bin/env python3
"""Quick target reachability precheck through the container's mihomo SOCKS.

Runs with the same mihomo config that capture.py will use.  Writes a CSV of
domains that returned 2xx/3xx so the full capture job can skip blocked sites.
"""
from __future__ import annotations

import argparse
import csv
import json
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import socks


def load_sites(path: Path) -> list[tuple[int, str]]:
    out = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for row in csv.reader(f):
            if len(row) >= 2 and row[0].strip().isdigit():
                out.append((int(row[0]), row[1].strip()))
            elif row and row[0].strip() and not row[0].startswith("#"):
                out.append((0, row[0].strip()))
    return out


def probe(rank: int, domain: str, timeout: float) -> dict:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/126.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "close",
    }
    last = ""
    for scheme in ("https", "http"):
        try:
            req = Request(f"{scheme}://{domain}/", headers=headers)
            with urlopen(
                req, timeout=timeout, context=ssl.create_default_context()
            ) as resp:
                status = int(resp.status)
                try:
                    resp.read(2048)
                except Exception:
                    pass
                if 200 <= status < 400:
                    return {
                        "rank": rank,
                        "domain": domain,
                        "ok": True,
                        "scheme": scheme,
                        "status": status,
                    }
                last = f"HTTP {status}"
        except HTTPError as exc:
            last = f"HTTP {exc.code}"
        except (URLError, socket.timeout, TimeoutError, ssl.SSLError, OSError) as exc:
            last = str(getattr(exc, "reason", exc))[:120]
        except Exception as exc:
            last = str(exc)[:120]
    return {"rank": rank, "domain": domain, "ok": False, "error": last}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--site-list", default="/app/sites/top1000.txt")
    ap.add_argument("--out", required=True)
    ap.add_argument("--protocol", default="unknown")
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--proxy-port", type=int, default=7890)
    args = ap.parse_args()

    # Wait for mihomo's SOCKS/mixed port.
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("127.0.0.1", args.proxy_port))
            s.close()
            break
        except Exception:
            time.sleep(0.5)
    else:
        print("mihomo SOCKS port not ready", file=sys.stderr)
        return 2

    socks.setdefaultproxy(
        socks.PROXY_TYPE_SOCKS5, "127.0.0.1", args.proxy_port, rdns=True
    )
    socket.socket = socks.socksocket
    socket.getaddrinfo = lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (a[0], a[1]))
    ]

    sites = load_sites(Path(args.site_list))
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {
            pool.submit(probe, rank, domain, args.timeout): (rank, domain)
            for rank, domain in sites
        }
        for i, fut in enumerate(as_completed(futs), 1):
            results.append(fut.result())
            if i % 100 == 0:
                ok = sum(1 for r in results if r["ok"])
                print(
                    f"  {i}/{len(sites)} probed, {ok} ok, "
                    f"{time.time()-t0:.0f}s",
                    flush=True,
                )

    results.sort(key=lambda r: r.get("rank", 0))
    reachable = [r for r in results if r["ok"]]
    with out_path.open("w", encoding="utf-8") as f:
        for r in reachable:
            f.write(f"{r['rank']},{r['domain']}\n")
    summary = {
        "protocol": args.protocol,
        "total": len(results),
        "reachable": len(reachable),
        "https": sum(1 for r in reachable if r.get("scheme") == "https"),
        "http": sum(1 for r in reachable if r.get("scheme") == "http"),
        "elapsed_s": round(time.time() - t0, 1),
        "results": results,
    }
    summary_path = out_path.with_suffix(".json")
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(
        json.dumps(
            {k: v for k, v in summary.items() if k != "results"},
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
