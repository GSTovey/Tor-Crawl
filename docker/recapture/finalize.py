#!/usr/bin/env python3
"""Generate the combined FINAL_REPORT.md / MANIFEST.csv / COUNTS.json."""
from __future__ import annotations

import csv
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUT = ROOT / "2026-10-28_Recapture"

MODES = [
    ("Pure_Proxy", "pure", False),
    ("Tor_over_Proxy", "top", False),
    ("Traffic_Pairs", "pairs", True),
    ("Tor_Direct/NonTor", "nontor", False),
]


def progress(mode: str, proto: str) -> dict:
    if mode == "nontor":
        name = "nontor__NonTor.json"
    else:
        name = f"{mode}__{proto}.json"
    p = OUT / "_meta" / "progress" / name
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def main() -> int:
    rows = []
    manifest = []
    for mode_dir, mode, is_pairs in MODES:
        base = OUT / mode_dir
        if not base.is_dir():
            continue
        protos = ["NonTor"] if mode == "nontor" else sorted(
            p.name for p in base.iterdir() if p.is_dir()
        )
        for proto in protos:
            pdir = base if mode == "nontor" else base / proto
            all_files = sorted(pdir.rglob("*.pcap"))
            if is_pairs:
                unit_files = [p for p in all_files if p.name.endswith("_post.pcap")]
                units = len(unit_files)
            else:
                units = len(all_files)
            domains = {p.parent.name for p in all_files}
            size = sum(p.stat().st_size for p in all_files)
            pr = progress(mode, proto)
            rows.append(
                {
                    "mode": mode,
                    "protocol": proto,
                    "units": units,
                    "files": len(all_files),
                    "domains": len(domains),
                    "bytes": size,
                    "target": pr.get("target", 5000),
                    "attempts": pr.get("attempts", ""),
                    "sites_done": pr.get("sites_done", ""),
                    "sites_total": pr.get("sites_total", ""),
                    "stop_reason": pr.get("stop_reason", ""),
                }
            )
            for pcap in all_files:
                manifest.append(
                    {
                        "mode": mode,
                        "protocol": proto,
                        "domain": pcap.parent.name,
                        "file": str(pcap.relative_to(OUT)).replace("\\", "/"),
                        "bytes": pcap.stat().st_size,
                    }
                )

    total_units = sum(r["units"] for r in rows)
    total_files = sum(r["files"] for r in rows)
    total_bytes = sum(r["bytes"] for r in rows)

    with (OUT / "MANIFEST.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f, fieldnames=["mode", "protocol", "domain", "file", "bytes"]
        )
        w.writeheader()
        w.writerows(manifest)

    counts = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "total_units": total_units,
        "total_files": total_files,
        "total_bytes": total_bytes,
        "jobs": rows,
        "missing_protocols": [],
        "excluded_protocols": ["mieru"],
        "missing_tor_modes": {
            "vless/trojan/ss/vmess": "5,000 pairs each via WebTunnel",
            "anytls/hysteria2": "549 / 258 pairs; no WebTunnel path",
            "mieru": "excluded by user on 2026-10-29",
        },
    }
    (OUT / "COUNTS.json").write_text(
        json.dumps(counts, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    lines = [
        "# 2026-10-28 Recapture — Final Report",
        "",
        f"Generated: {counts['generated_at']}",
        "",
        f"**Total valid units: {total_units:,}**  ",
        f"**Total PCAP files: {total_files:,}**  ",
        f"**Total size: {total_bytes/1024**3:.2f} GiB**",
        "",
        "| Mode | Protocol | Valid units | Files | Domains | Size (MiB) | Target | Attempts | Sites | Stop |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for r in rows:
        sites = (
            f"{r['sites_done']}/{r['sites_total']}"
            if r["sites_done"] != ""
            else ""
        )
        lines.append(
            f"| {r['mode']} | {r['protocol']} | {r['units']:,} | {r['files']:,} | "
            f"{r['domains']:,} | {r['bytes']/1024**2:.1f} | {r['target']} | "
            f"{r['attempts']} | {sites} | {r['stop_reason']} |"
        )
    lines += [
        "",
        "For Traffic_Pairs a unit is one `_pre.pcap` + `_post.pcap` pair; the file",
        "count is twice the unit count.",
        "",
        "## Validation",
        "",
        "- Only HTTP 2xx/3xx requests with a matching transport capture were kept.",
        "- Each PCAP contains bidirectional payload to the selected proxy node endpoint",
        "  (TCP, or UDP/QUIC for Hysteria2); the endpoint must be public and match the",
        "  node's port/range.",
        "- Any traffic to host Clash `192.168.65.254:7897` causes rejection.",
        "- Invalid attempts are deleted and logged in `_meta/<job>_failures.jsonl`.",
        "- `_pilot/` contains manually verified samples (Pure, NonTor, ToP and Pairs).",
        "",
        "## Tor modes",
        "",
        "- **VLESS / Trojan / SS / VMess** Traffic_Pairs: **5,000 pairs each**",
        "  using the user-provided WebTunnel bridges through local direct fronts.",
        "- **AnyTLS / Hysteria2** Traffic_Pairs: partial, 549 / 258 pairs; their",
        "  nodes could not carry WebTunnel.",
        "- **Tor_over_Proxy** was stopped earlier to prioritize Pairs; partial data",
        "  remains in `Tor_over_Proxy/`.",
        "",
        "## Excluded / limited",
        "",
        "- **Mieru** — explicitly excluded by the user on 2026-10-29. Its partial",
        "  captures and mita artifacts are in `_excluded_mieru/` and are not counted.",
        "- AnyTLS/Hysteria2 Pairs remain partial; no WebTunnel-capable exit was found.",
        "- ToP remains partial; it was deliberately stopped for the Pairs phase.",
        "",
        "See `NODE_TEST_REPORT.md` and `MISSING_AND_NEXT_STEPS.md` for details.",
        "",
        "## Layout",
        "",
        "```",
        "Pure_Proxy/<protocol>/<domain>/<NNN>.pcap",
        "Tor_over_Proxy/<protocol>/<domain>/<NNN>.pcap",
        "Traffic_Pairs/<protocol>/<domain>/<NNN>_pre.pcap + <NNN>_post.pcap",
        "Tor_Direct/NonTor/<domain>/<NNN>.pcap",
        "_pilot/                  validation samples",
        "_preflight/              node inventory/tests, runtime configs, reachable lists",
        "_meta/                   logs, progress, JSONL metadata",
        "_excluded_mieru/         excluded Mieru data/artifacts (not in manifest)",
        "MANIFEST.csv             per-file manifest",
        "COUNTS.json              machine-readable counts",
        "```",
        "",
        "Old top-level `Pure_Proxy/`, `Tor_over_Proxy/`, `Traffic_Pairs/`, `Tor_Direct/`",
        "folders were not modified.",
        "",
    ]
    (OUT / "FINAL_REPORT.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({k: v for k, v in counts.items() if k != "jobs"}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
