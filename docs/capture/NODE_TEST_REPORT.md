# Node test report — 2026-10-28 recapture

## Method

- Candidate nodes were loaded into mihomo and tested with their real proxy handshake
  through the controller delay API (`/proxies/<id>/delay`).
- Tor tests ran mihomo + Tor with `Socks5Proxy 127.0.0.1:7890`; success required
  bootstrap plus a real request through Tor.
- Plain-SS only: SS-over-plugin/WebSocket variants were excluded to keep the
  wire label true.
- Mieru was later excluded by user request; its artifacts are in
  `_excluded_mieru/` and are not part of the dataset.

## HTTP reachability by protocol

| Protocol | Candidate nodes | HTTP-working | Median delay | Notes |
|---|---:|---:|---:|---|
| vless | 214 | 17 | 76 | 17 working subscription VLESS nodes; Pure target reached. |
| ss | 258 | 0 | — | 0 working public nodes; solved by a self-hosted Xray SS server + hy2 upstream. |
| trojan | 225 | 8 | 510 | 8 working public nodes; Pure expanded with a self-hosted Xray Trojan server. |
| anytls | 100 | 7 | 461 | 7 working user-batch2 VIP88 AnyTLS nodes. |
| hysteria2 | 62 | 36 | 208 | 36 working user-batch2 VIP88 Hysteria2 nodes. |
| mieru | 0 | 0 | — | Excluded by the user on 2026-10-29; removed from the dataset. |

## Selected public nodes (Pure mode, before self-host expansion)

| Protocol | IDs |
|---|---|
| vless | vl0196, vl0198, vl0201, vl0195, vl0200, vl0179, vl0182, vl0203, vl0194, vl0176, vl0152, vl0173, vl0197, vl0146, vl0202, vl0199, vl0151 |
| ss | — |
| trojan | tr0126, tr0170, tr0199, tr0177, tr0202, tr0129, tr0004, tr0008 |
| anytls | an0004, an0005, an0001, an0008, an0002, an0003, an0006 |
| hysteria2 | hy0030, hy0031, hy0028, hy0022, hy0025, hy0021, hy0024, hy0038, hy0037, hy0008, hy0035, hy0009, hy0039, hy0007, hy0027, hy0034, hy0016 |
| mieru | — |

## Plain Tor bootstrap (without bridges)

| Protocol | Tested | Tor-capable | Result |
|---|---:|---:|---|
| vless | 6 | 0 | stuck at 10% TLS handshake / timeout |
| anytls | 6 | 0 | stuck at 10% TLS handshake / timeout |
| hysteria2 | 6 | 0 | stuck at 10% TLS handshake / timeout |
| trojan | 6 | 0 | stuck at 10% TLS handshake / timeout |

Plain Tor also failed through the own Trojan node `45.76.51.23` (stuck at 10%).

## User-provided obfs4 bridges (2026-10-29)

| Node | Protocol | Bootstrap | IsTor | Result |
|---|---|---|---|---|
| an0004 | AnyTLS | 100% | true | **success** |
| hy0030 | Hysteria2 | 100% | true | **success** |
| vl0196 | VLESS | 2% | — | public exit could not reach bridges |
| tr0004 | Trojan | 2% | — | public exit could not reach bridges |
| tr0126 | Trojan | 2% | — | public exit could not reach bridges |

These bridges are used by AnyTLS/Hysteria2 ToP/Pairs directly, and by the
self-hosted local fronts for VLESS/Trojan/SS/VMess ToP/Pairs.

## Self-hosted fronts + Hysteria2 upstream

A local Xray server on Docker network `recapture-servers` provides Trojan
(8443 TLS), Shadowsocks (8388), VLESS (8444) and VMess (8445) inbounds.
Its outbound is a SOCKS upstream to a local mihomo running the Hysteria2
node `hy0030`. This gives:

- Pure Trojan/SS/VMess with real wire protocols and broad target reachability.
- VLESS/Trojan/SS/VMess Tor_over_Proxy and Traffic_Pairs: Tor + user obfs4
  bridges -> mihomo local front -> Xray server -> hy2 upstream -> bridge.

The local fronts were verified with the same `tor_test.py` bridge test
(Bootstrap 100%, IsTor=true, HTTP 204/200).

## Direct reachability (NonTor)

- Tranco top-1000 direct probe: **804/1000** reachable.
- NonTor runs against this list; a top-up pass will fill any shortfall.

## User batch2 notes

- VIP88 VLESS `xhttp` + `mlkem768x25519plus` nodes were TCP-reachable but
  mihomo could not complete their handshake; they were not used.
- One VMess URI in batch2 was skipped; VMess is now covered by the
  self-hosted Xray VMess front instead.
