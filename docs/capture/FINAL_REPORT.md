# 2026-10-28 Recapture — Final Report

Generated: 2026-10-31T20:08:55+0800

**Total valid units: 57,872**  
**Total PCAP files: 78,899**  
**Total size: 18.56 GiB**

| Mode | Protocol | Valid units | Files | Domains | Size (MiB) | Target | Attempts | Sites | Stop |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| pure | anytls | 5,000 | 5,000 | 558 | 1848.5 | 5000 | 5016 | 560/663 | target |
| pure | hysteria2 | 5,000 | 5,000 | 626 | 2501.9 | 5000 | 5015 | 628/716 | target |
| pure | ss | 5,216 | 5,216 | 542 | 977.4 | 5000 | 5356 | 676/804 | target |
| pure | trojan | 5,289 | 5,289 | 551 | 1074.6 | 5000 | 5116 | 664/804 | target |
| pure | vless | 5,000 | 5,000 | 627 | 2054.8 | 5000 | 5022 | 629/728 | target |
| pure | vmess | 5,000 | 5,000 | 448 | 802.0 | 5000 | 1107 | 182/924 | target |
| top | anytls | 439 | 439 | 44 | 172.5 | 5000 | 1239 | 310/1000 |  |
| top | hysteria2 | 214 | 214 | 24 | 185.7 | 5000 | 1117 | 320/1000 |  |
| top | ss | 183 | 183 | 19 | 81.5 | 5000 | 1066 | 312/1000 |  |
| top | trojan | 156 | 156 | 16 | 73.2 | 5000 | 1038 | 309/1000 |  |
| top | vless | 211 | 211 | 22 | 92.1 | 5000 | 1109 | 320/1000 |  |
| top | vmess | 137 | 137 | 14 | 72.9 | 5000 | 1019 | 306/1000 |  |
| pairs | anytls | 549 | 1,098 | 57 | 466.6 | 5000 | 1310 | 307/1000 |  |
| pairs | hysteria2 | 258 | 516 | 27 | 329.0 | 5000 | 1144 | 320/1000 |  |
| pairs | ss | 5,060 | 10,120 | 511 | 1790.7 | 5000 | 7793 | 2293/5000 | target |
| pairs | trojan | 5,040 | 10,080 | 509 | 1695.5 | 5000 | 7718 | 2258/5000 | target |
| pairs | vless | 5,080 | 10,160 | 513 | 1747.2 | 5000 | 7634 | 2248/5000 | target |
| pairs | vmess | 5,040 | 10,080 | 506 | 1753.5 | 5000 | 7635 | 2228/5000 | target |
| nontor | NonTor | 5,000 | 5,000 | 618 | 1280.8 | 5000 | 273 | 109/804 | target |

For Traffic_Pairs a unit is one `_pre.pcap` + `_post.pcap` pair; the file
count is twice the unit count.

## Validation

- Only HTTP 2xx/3xx requests with a matching transport capture were kept.
- Each PCAP contains bidirectional payload to the selected proxy node endpoint
  (TCP, or UDP/QUIC for Hysteria2); the endpoint must be public and match the
  node's port/range.
- Any traffic to host Clash `192.168.65.254:7897` causes rejection.
- Invalid attempts are deleted and logged in `_meta/<job>_failures.jsonl`.
- `_pilot/` contains manually verified samples (Pure, NonTor, ToP and Pairs).

## Tor modes

- **VLESS / Trojan / SS / VMess** Traffic_Pairs: **5,000 pairs each**
  using the user-provided WebTunnel bridges through local direct fronts.
- **AnyTLS / Hysteria2** Traffic_Pairs: partial, 549 / 258 pairs; their
  nodes could not carry WebTunnel.
- **Tor_over_Proxy** was stopped earlier to prioritize Pairs; partial data
  remains in `Tor_over_Proxy/`.

## Excluded / limited

- **Mieru** — explicitly excluded by the user on 2026-10-29. Its partial
  captures and mita artifacts are in `_excluded_mieru/` and are not counted.
- AnyTLS/Hysteria2 Pairs remain partial; no WebTunnel-capable exit was found.
- ToP remains partial; it was deliberately stopped for the Pairs phase.

See `NODE_TEST_REPORT.md` and `MISSING_AND_NEXT_STEPS.md` for details.

## Layout

```
Pure_Proxy/<protocol>/<domain>/<NNN>.pcap
Tor_over_Proxy/<protocol>/<domain>/<NNN>.pcap
Traffic_Pairs/<protocol>/<domain>/<NNN>_pre.pcap + <NNN>_post.pcap
Tor_Direct/NonTor/<domain>/<NNN>.pcap
_pilot/                  validation samples
_preflight/              node inventory/tests, runtime configs, reachable lists
_meta/                   logs, progress, JSONL metadata
_excluded_mieru/         excluded Mieru data/artifacts (not in manifest)
MANIFEST.csv             per-file manifest
COUNTS.json              machine-readable counts
```

Old top-level `Pure_Proxy/`, `Tor_over_Proxy/`, `Traffic_Pairs/`, `Tor_Direct/`
folders were not modified.
