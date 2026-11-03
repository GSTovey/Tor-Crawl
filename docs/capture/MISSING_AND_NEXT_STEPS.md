# Final status — capture complete

All capture jobs are stopped and the final manifest/report has been generated.

## Included and complete

- Pure: VLESS, AnyTLS, Hysteria2, Trojan, SS, VMess — all at or above 5,000.
- Pairs: VLESS, Trojan, SS, VMess — 5,000+ pairs each.
- NonTor: 5,000.

## Partial / stopped

- ToP: partial data retained from the earlier phase (1,340 units total).
- Pairs AnyTLS / Hysteria2: 549 / 258 pairs; no WebTunnel-capable path was found
  for those two protocol fronts, so they were not resumed.
- Mieru: excluded by the user on 2026-10-29. Its 78 PCAPs and mita artifacts are
  in `_excluded_mieru/` and are not counted.

## Final files

- `FINAL_REPORT.md` — counts and per-mode/protocol table
- `COUNTS.json` — machine-readable counts
- `MANIFEST.csv` — one row per valid PCAP
- `_excluded_mieru/` — excluded Mieru data; safe to delete
- Old top-level folders (`Pure_Proxy/`, `Tor_over_Proxy/`, `Traffic_Pairs/`,
  `Tor_Direct/`) were not modified.

No user action is required.
