#!/usr/bin/env python3
"""Join MANIFEST.csv with _meta/*.jsonl into a per-PCAP capture index.

The dataset does not store explicit task_id / pair_id / session_id fields.
This script derives stable keys from the existing job/domain/index fields and
writes them as *derived* columns.  In particular, `session_id_derived` is NOT a
protocol-level session identifier; it identifies one capture unit (one HTTP
transaction, or one pre/post pair).

Usage (from the directory that contains MANIFEST.csv and _meta/):
    python3 build_capture_index.py --root . --out ../capture_index.csv
"""

import argparse
import csv
import glob
import json
import os
import re
from datetime import datetime, timedelta, timezone

CST = timezone(timedelta(hours=8))

FIELDS = [
    "capture_id",
    "task_id",
    "pair_id",
    "session_id_derived",
    "condition",
    "wrapper",
    "tor_layer",
    "transport",
    "domain",
    "index",
    "file_role",
    "node",
    "ts_utc",
    "ts_cst",
    "http_ok",
    "http_status",
    "scheme",
    "duration_s",
    "body_len",
    "pcap_bytes",
    "validator_valid",
    "matched_packets",
    "remote_endpoints",
    "local_endpoints",
]


def derive_condition(mode: str, node: str) -> str:
    if mode == "nontor":
        return "nontor_direct"
    if mode == "pure":
        if node.startswith("self-"):
            return "pure_selfhost_local"
        if node.startswith("direct-"):
            return "pure_selfhost_direct"
        return "pure_public_node"
    if mode == "top":
        if node.startswith("self-"):
            return "top_selfhost"
        return "top_public_node"
    if mode == "pairs":
        if node.startswith("direct-"):
            return "pairs_webtunnel"
        if node.startswith("self-"):
            return "pairs_selfhost_local"
        return "pairs_public_obfs4"
    return "unknown"


def derive_tor_layer(mode: str, node: str) -> str:
    if mode in ("pure", "nontor"):
        return "none"
    if mode == "top":
        return "obfs4"
    if mode == "pairs":
        if node.startswith("direct-"):
            return "webtunnel"
        return "obfs4"
    return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--out", default="capture_index.csv")
    parser.add_argument("--pcap-prefix", default="pcap/")
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    manifest_path = os.path.join(root, "MANIFEST.csv")
    meta_dir = os.path.join(root, "_meta")

    meta = {}
    records = 0
    for path in sorted(glob.glob(os.path.join(meta_dir, "*.jsonl"))):
        if path.endswith("_failures.jsonl"):
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip():
                    continue
                d = json.loads(line)
                key = (d.get("mode"), d.get("protocol"), d.get("domain"), d.get("index"))
                meta[key] = d
                records += 1

    rows = []
    missing = 0
    with open(manifest_path, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            mode = r["mode"]
            proto = r["protocol"]
            domain = r["domain"]
            file_path = r["file"].replace("\\", "/")
            base = os.path.basename(file_path)
            m = re.match(r"(\d+)(?:_(pre|post))?\.pcap$", base)
            if not m:
                missing += 1
                continue
            index = int(m.group(1))
            role = m.group(2) or "single"

            d = meta.get((mode, proto, domain, index))
            if d is None:
                missing += 1
                continue

            node = d.get("node") or ""
            validator = d.get("validator_pre") if role == "pre" else d.get("validator_post")
            validator = validator or {}
            summary = validator.get("summary") or {}

            if role == "pre":
                transport = "tcp"
            elif summary.get("udp_packets", 0) > 0:
                transport = "udp"
            elif summary.get("tcp_packets", 0) > 0:
                transport = "tcp"
            else:
                transport = ""

            ts = d.get("ts") or ""
            ts_cst = ""
            if ts:
                try:
                    ts_cst = (
                        datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S%z")
                        .astimezone(CST)
                        .strftime("%Y-%m-%d %H:%M:%S")
                    )
                except ValueError:
                    pass

            http = d.get("http") or {}
            task_id = d.get("job") or f"{mode}__{proto}"
            session_key = f"{task_id}|{domain}|{index}"

            rows.append(
                {
                    "capture_id": args.pcap_prefix + file_path,
                    "task_id": task_id,
                    "pair_id": session_key if mode == "pairs" else "",
                    "session_id_derived": session_key,
                    "condition": derive_condition(mode, node),
                    "wrapper": "none" if mode == "nontor" else proto,
                    "tor_layer": derive_tor_layer(mode, node),
                    "transport": transport,
                    "domain": domain,
                    "index": index,
                    "file_role": role,
                    "node": node,
                    "ts_utc": ts,
                    "ts_cst": ts_cst,
                    "http_ok": http.get("ok"),
                    "http_status": http.get("status"),
                    "scheme": d.get("scheme"),
                    "duration_s": http.get("duration"),
                    "body_len": http.get("body_len"),
                    "pcap_bytes": r["bytes"],
                    "validator_valid": validator.get("valid"),
                    "matched_packets": summary.get("matched_packets"),
                    "remote_endpoints": json.dumps(
                        summary.get("remote_endpoints") or {}, ensure_ascii=False
                    ),
                    "local_endpoints": json.dumps(
                        summary.get("local_endpoints") or {}, ensure_ascii=False
                    ),
                }
            )

    with open(args.out, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(
        f"wrote {args.out}: {len(rows)} rows, "
        f"{missing} manifest rows without metadata, {records} metadata records"
    )


if __name__ == "__main__":
    main()
