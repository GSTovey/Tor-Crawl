# WebTunnel Pairs phase

Updated: 2026-10-31 17:56:32+0800

Chain: Tor + user WebTunnel bridges -> mihomo local front -> Xray direct server -> WebTunnel URL
Site list: Umbrella top 5000; timeout 30s; retries 2

| Job | Status | Captured pairs | Target | Sites | Last error |
|---|---|---:|---:|---:|---|
| pairs-vless-wt | done | 5000 | 5000 | 2248/5000 | https:HTTP 404 | http:Socket error: timed out |
| pairs-trojan-wt | done | 5000 | 5000 | 2258/5000 | https:HTTP 403 | http:HTTP 403 |
| pairs-ss-wt | done | 5000 | 5000 | 2293/5000 | https:[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, certificate is  |
| pairs-vmess-wt | done | 5000 | 5000 | 2228/5000 | https:HTTP 401 | http:HTTP 401 |

STOP file: G:\Tor_Crawl\2026-10-28_Recapture\_meta\STOP
