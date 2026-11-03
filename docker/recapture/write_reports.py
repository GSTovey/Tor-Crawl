#!/usr/bin/env python3
"""Write NODE_TEST_REPORT.md, MISSING_AND_NEXT_STEPS.md and README.md."""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUT = ROOT / "2026-10-28_Recapture"
PRE = OUT / "_preflight"
PROTOCOLS = ["vless", "ss", "trojan", "anytls", "hysteria2", "mieru"]


def load_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def count_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return sum(1 for line in f if line.strip() and not line.startswith("#"))


def main() -> int:
    summary = load_json(PRE / "node_tests_summary.json", {}) or {}
    selected = load_json(PRE / "selected_nodes.json", {}) or {}
    tor_summary = load_json(PRE / "tor_tests_summary.json", {}) or {}
    direct = load_json(PRE / "direct_check.json", {}) or {}

    notes = {
        "vless": "17 working subscription VLESS nodes; Pure target reached.",
        "ss": "0 working public nodes; solved by a self-hosted Xray SS server + hy2 upstream.",
        "trojan": "8 working public nodes; Pure expanded with a self-hosted Xray Trojan server.",
        "anytls": "7 working user-batch2 VIP88 AnyTLS nodes.",
        "hysteria2": "36 working user-batch2 VIP88 Hysteria2 nodes.",
        "mieru": "Excluded by the user on 2026-10-29; removed from the dataset.",
    }

    lines = [
        "# Node test report — 2026-10-28 recapture",
        "",
        "## Method",
        "",
        "- Candidate nodes were loaded into mihomo and tested with their real proxy handshake",
        "  through the controller delay API (`/proxies/<id>/delay`).",
        "- Tor tests ran mihomo + Tor with `Socks5Proxy 127.0.0.1:7890`; success required",
        "  bootstrap plus a real request through Tor.",
        "- Plain-SS only: SS-over-plugin/WebSocket variants were excluded to keep the",
        "  wire label true.",
        "- Mieru was later excluded by user request; its artifacts are in",
        "  `_excluded_mieru/` and are not part of the dataset.",
        "",
        "## HTTP reachability by protocol",
        "",
        "| Protocol | Candidate nodes | HTTP-working | Median delay | Notes |",
        "|---|---:|---:|---:|---|",
    ]
    for proto in PROTOCOLS:
        nt = load_json(PRE / "node_tests" / f"{proto}.json", {}) or {}
        lines.append(
            f"| {proto} | {nt.get('total', 0)} | {nt.get('ok', 0)} | "
            f"{nt.get('median_delay_ms') if nt.get('median_delay_ms') is not None else '—'} | "
            f"{notes.get(proto, '')} |"
        )
    lines += [
        "",
        "## Selected public nodes (Pure mode, before self-host expansion)",
        "",
        "| Protocol | IDs |",
        "|---|---|",
    ]
    for proto in PROTOCOLS:
        ids = selected.get("protocols", {}).get(proto, {}).get("pure", [])
        if proto == "mieru":
            ids = []
        lines.append(f"| {proto} | {', '.join(ids) if ids else '—'} |")

    lines += [
        "",
        "## Plain Tor bootstrap (without bridges)",
        "",
        "| Protocol | Tested | Tor-capable | Result |",
        "|---|---:|---:|---|",
    ]
    for proto in ("vless", "anytls", "hysteria2", "trojan"):
        t = tor_summary.get("protocols", {}).get(proto, {})
        lines.append(
            f"| {proto} | {t.get('tested', 0)} | {t.get('success', 0)} | "
            f"{'OK' if t.get('success') else 'stuck at 10% TLS handshake / timeout'} |"
        )
    lines += [
        "",
        "Plain Tor also failed through the self-hosted Trojan node (stuck at 10%).",
        "",
        "## User-provided obfs4 bridges (2026-10-29)",
        "",
        "| Node | Protocol | Bootstrap | IsTor | Result |",
        "|---|---|---|---|---|",
        "| an0004 | AnyTLS | 100% | true | **success** |",
        "| hy0030 | Hysteria2 | 100% | true | **success** |",
        "| vl0196 | VLESS | 2% | — | public exit could not reach bridges |",
        "| tr0004 | Trojan | 2% | — | public exit could not reach bridges |",
        "| tr0126 | Trojan | 2% | — | public exit could not reach bridges |",
        "",
        "These bridges are used by AnyTLS/Hysteria2 ToP/Pairs directly, and by the",
        "self-hosted local fronts for VLESS/Trojan/SS/VMess ToP/Pairs.",
        "",
        "## Self-hosted fronts + Hysteria2 upstream",
        "",
        "A local Xray server on Docker network `recapture-servers` provides Trojan",
        "(8443 TLS), Shadowsocks (8388), VLESS (8444) and VMess (8445) inbounds.",
        "Its outbound is a SOCKS upstream to a local mihomo running the Hysteria2",
        "node `hy0030`. This gives:",
        "",
        "- Pure Trojan/SS/VMess with real wire protocols and broad target reachability.",
        "- VLESS/Trojan/SS/VMess Tor_over_Proxy and Traffic_Pairs: Tor + user obfs4",
        "  bridges -> mihomo local front -> Xray server -> hy2 upstream -> bridge.",
        "",
        "The local fronts were verified with the same `tor_test.py` bridge test",
        "(Bootstrap 100%, IsTor=true, HTTP 204/200).",
        "",
        "## Direct reachability (NonTor)",
        "",
        f"- Tranco top-1000 direct probe: **{direct.get('reachable', '?')}/"
        f"{direct.get('total', '?')}** reachable.",
        "- NonTor runs against this list; a top-up pass will fill any shortfall.",
        "",
        "## User batch2 notes",
        "",
        "- VIP88 VLESS `xhttp` + `mlkem768x25519plus` nodes were TCP-reachable but",
        "  mihomo could not complete their handshake; they were not used.",
        "- One VMess URI in batch2 was skipped; VMess is now covered by the",
        "  self-hosted Xray VMess front instead.",
        "",
    ]
    (OUT / "NODE_TEST_REPORT.md").write_text("\n".join(lines), encoding="utf-8")

    missing = [
        "# Status, exclusions and next steps",
        "",
        "## Included protocols",
        "",
        "VLESS, AnyTLS, Hysteria2, Trojan, Shadowsocks, VMess.",
        "",
        "## Excluded",
        "",
        "- **Mieru** — explicitly excluded by the user on 2026-10-29.",
        "  Its partial captures, mita server binary/config and test artifacts were",
        "  moved to `2026-10-28_Recapture/_excluded_mieru/` and are not counted in",
        "  `MANIFEST.csv` / `FINAL_REPORT.md`. The folder can be deleted safely.",
        "",
        "## Capture status",
        "",
        "| Item | Status |",
        "|---|---|",
        "| Pure VLESS / AnyTLS / Hysteria2 | 5,000 each (done) |",
        "| Pure Trojan / SS / VMess | self-hosted Xray + hy2 upstream, running to 5,000 |",
        "| Tor_over_Proxy / Traffic_Pairs AnyTLS/Hysteria2 | running via user obfs4 bridges |",
        "| Tor_over_Proxy / Traffic_Pairs VLESS/Trojan/SS/VMess | running via local front + hy2 + bridges |",
        "| Tor_Direct/NonTor | running; top-up to 5,000 after site exhaustion |",
        "| Mieru | excluded |",
        "",
        "## User action",
        "",
        "None required for the included protocols. The supervisors run up to 72 h,",
        "retry failed containers, and stop on the shared STOP file or a low-disk",
        "condition.",
        "",
        "Optional: if a specific Tor mode finishes short of 5,000 before the 72 h",
        "cap, a faster bridge/exit or a second bridge line would help. This is not",
        "blocking the current run.",
        "",
        "## Stop / resume",
        "",
        "```bash",
        "# stop everything gracefully:",
        "touch 2026-10-28_Recapture/_meta/STOP",
        "",
        "# after all supervisors finish, build the combined manifest/report:",
        "python docker/recapture/finalize.py",
        "```",
        "",
    ]
    (OUT / "MISSING_AND_NEXT_STEPS.md").write_text("\n".join(missing), encoding="utf-8")

    readme = [
        "# 2026-10-28 Recapture",
        "",
        "New dataset under this folder; old top-level capture folders are untouched.",
        "",
        "## Layout",
        "",
        "```",
        "2026-10-28_Recapture/",
        "  Pure_Proxy/<protocol>/<domain>/<NNN>.pcap",
        "  Tor_over_Proxy/<protocol>/<domain>/<NNN>.pcap",
        "  Traffic_Pairs/<protocol>/<domain>/<NNN>_pre.pcap + <NNN>_post.pcap",
        "  Tor_Direct/NonTor/<domain>/<NNN>.pcap",
        "  _pilot/                  verified validation samples",
        "  _preflight/              node tests, runtime configs, reachable lists",
        "  _meta/                   logs, progress, per-capture JSONL metadata",
        "  _excluded_mieru/         Mieru stopped/excluded by user; not in dataset",
        "  MANIFEST.csv",
        "  COUNTS.json",
        "  FINAL_REPORT.md",
        "  STATUS*.md",
        "```",
        "",
        "## Validation",
        "",
        "A PCAP is kept only if:",
        "",
        "1. HTTP(S) status is 200–399.",
        "2. The capture has bidirectional transport payload to the selected proxy",
        "   endpoint (TCP, or UDP/QUIC for Hysteria2).",
        "3. The endpoint matches the selected node/port or the allowed self-hosted",
        "   endpoint.",
        "4. No host-Clash `192.168.65.254:7897` traffic is present.",
        "5. No RST before data.",
        "",
        "Invalid attempts are deleted and logged in `_meta/<job>_failures.jsonl`.",
        "",
        "## Topologies",
        "",
        "- AnyTLS/Hysteria2 Tor modes: public node + user obfs4 bridges.",
        "- VLESS/Trojan/SS/VMess Tor modes: Tor + user bridges -> local mihomo front",
        "  -> local Xray server -> Hysteria2 upstream -> bridge/Tor.",
        "- Trojan/SS/VMess Pure: local mihomo front -> local Xray server",
        "  -> Hysteria2 upstream -> target.",
        "- Mieru: stopped and excluded; see `_excluded_mieru/`.",
        "",
    ]
    (OUT / "README.md").write_text("\n".join(readme), encoding="utf-8")
    print("reports written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
