#!/usr/bin/env python3
"""Pre-filter Tranco domains that are reachable directly (no proxy/Tor).

Used for the NonTor dataset.  The result is intentionally conservative: the
crawler will still verify each request and only keep 2xx/3xx PCAPs.
"""
from __future__ import annotations

import argparse
import csv
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


def load_sites(path: Path) -> list[tuple[int, str]]:
    out = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for row in csv.reader(f):
            if len(row) >= 2 and row[0].strip().isdigit():
                out.append((int(row[0]), row[1].strip()))
            elif row and row[0].strip() and not row[0].startswith("#"):
                out.append((0, row[0].strip()))
    return out


def probe(domain: str, timeout: float) -> dict:
    for port, scheme in ((443, "https"), (80, "http")):
        t0 = time.monotonic()
        try:
            s = socket.create_connection((domain, port), timeout=timeout)
            s.close()
            return {
                "domain": domain,
                "ok": True,
                "port": port,
                "scheme": scheme,
                "elapsed": round(time.monotonic() - t0, 3),
            }
        except Exception as exc:
            last = str(exc)[:120]
    return {"domain": domain, "ok": False, "error": last}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--site-list",
        default=r"g:/Tor_Crawl/docker/configs/top1000.txt",
    )
    ap.add_argument(
        "--out-dir",
        default=r"g:/Tor_Crawl/2026-10-28_Recapture/_preflight",
    )
    ap.add_argument("--workers", type=int, default=50)
    ap.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args()

    sites = load_sites(Path(args.site_list))
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(probe, d, args.timeout): (rank, d) for rank, d in sites}
        for i, fut in enumerate(as_completed(futures), 1):
            rank, domain = futures[fut]
            r = fut.result()
            r["rank"] = rank
            results.append(r)
            if i % 100 == 0:
                ok = sum(1 for x in results if x["ok"])
                print(f"  {i}/{len(sites)} probed, {ok} reachable, {time.time()-t0:.0f}s", flush=True)

    results.sort(key=lambda r: r.get("rank", 0))
    reachable = [r for r in results if r["ok"]]
    with (out_dir / "direct_reachable.txt").open("w", encoding="utf-8") as f:
        for r in reachable:
            f.write(f"{r['rank']},{r['domain']}\n")
    summary = {
        "total": len(results),
        "reachable": len(reachable),
        "https": sum(1 for r in reachable if r["scheme"] == "https"),
        "http": sum(1 for r in reachable if r["scheme"] == "http"),
        "elapsed_s": round(time.time() - t0, 1),
        "results": results,
    }
    (out_dir / "direct_check.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps({k: v for k, v in summary.items() if k != "results"}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
