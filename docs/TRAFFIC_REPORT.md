# TorCrawl 流量抓取完整报告

## 目录结构

```
g:\Tor_Crawl\
├── Tor_over_Proxy/    # ToP: Tor 经代理协议封装后的流量
├── Pure_Proxy/        # 纯代理直连流量（无 Tor）
├── Tor_Direct/        # Tor 直接流量 / 普通直连流量
├── Traffic_Pairs/     # 流量对：同一请求的代理前/后双视角
└── TRAFFIC_REPORT.md  # 本报告
```

---

## 一、Tor_over_Proxy（ToP — Tor over Proxy）

**链路**: `爬虫 → Tor SOCKS5 → Xray 代理封装 → 远程服务器 → Tor 网络 → 目标`

Tor 将流量加密后交给 Xray，Xray 用对应协议封装后发出。PCAP 抓取点在容器 `eth0`，捕获的是**代理协议加密后的 Tor 流量**。

| 协议 | PCAP 数量 | 站点数 | 说明 |
|------|-----------|--------|------|
| VLESS | 10,000 | 1,000 | 宿主机 Clash 代理 (REALITY/XTLS) |
| Trojan | 10,000 | 1,000 | 用户自有节点 `<redacted>` |
| Shadowsocks | 10,000 | 1,000 | ssidwork 付费订阅 |
| Hysteria2 | 10,000 | 1,000 | 宿主机 Clash 代理 (QUIC) |
| Mieru | 10,000 | 1,000 | 宿主机代理 |
| VMess | 10,000 | 1,000 | VIP88 节点 + obfs4 网桥 |
| AnyTLS | 10,000 | 1,000 | 宿主机 Clash 代理 |
| **小计** | **70,000** | **7,000** | |

> VMess 受机场 DPI 阻断，通过 obfs4 网桥（Tor 流量伪装为随机字节）绕过。

---

## 二、Pure_Proxy（纯代理直连流量）

**链路**: `爬虫 → Xray 代理封装 → 远程服务器 → 目标`

无 Tor 环节，HTTP 请求直接通过代理发出。抓取点在容器 `eth0`，捕获的是**纯代理协议流量**（不含 Tor 层）。

| 协议 | PCAP 数量 | 站点数 | 说明 |
|------|-----------|--------|------|
| VLESS | 10,000 | 1,000 | 宿主机 Clash |
| Trojan | 10,000 | 1,000 | 用户自有节点 |
| Shadowsocks | 10,000 | 1,000 | ssidwork 订阅 |
| Hysteria2 | 10,000 | 1,000 | 宿主机 Clash |
| VMess | 10,000 | 1,000 | VIP88 节点 |
| Mieru | 10,000 | 1,000 | 宿主机代理 |
| AnyTLS | 10,000 | 1,000 | 宿主机 Clash |
| **小计** | **70,000** | **7,000** | |

> Pure 模式不需要 Tor，抓取速度比 ToP 快 3-5 倍。

---

## 三、Tor_Direct（直连流量）

| 子目录 | PCAP 数量 | 站点数 | 链路 |
|--------|-----------|--------|------|
| NonTor | 10,000 | 1,000 | 爬虫 → 宿主机 Clash → 目标（纯 HTTP，无 Tor 无代理封装） |
| **小计** | **10,000** | **1,000** | |

---

## 四、Traffic_Pairs（流量对 — 代理前/后双视角）

**链路**: `爬虫 → Tor SOCKS5 → Xray 代理封装 → 远程 → Tor 网络 → 目标`

同一 HTTP 请求同时抓取两个位置：
- **`_pre.pcap`** — `lo` 接口，Tor 到 Xray 的流量（**代理封装前**，Tor 处理后）
- **`_post.pcap`** — `eth0` 接口，Xray 到远程服务器的流量（**代理封装后**）

文件命名: `{序号}_pre.pcap` / `{序号}_post.pcap`

```
Traffic_Pairs/<protocol>/<domain>/
  001_pre.pcap    001_post.pcap
  002_pre.pcap    002_post.pcap
  ...
  010_pre.pcap    010_post.pcap
```

| 协议 | 流量对 | 站点 | 文件数 |
|------|--------|------|--------|
| VLESS | 10,000 | 1,000 | 20,000 |
| Trojan | 10,000 | 1,000 | 20,000 |
| Shadowsocks | 10,000 | 1,000 | 20,000 |
| Hysteria2 | 10,000 | 1,000 | 20,000 |
| Mieru | 10,000 | 1,000 | 20,000 |
| VMess | 10,000 | 1,000 | 20,000 |
| AnyTLS | 10,000 | 1,000 | 20,000 |
| **小计** | **70,000 对** | **7,000** | **140,000** |

> `_pre` 和 `_post` 的大小不同——代理封装改变了数据包结构和大小，可直接对比分析。

---

## 五、协议覆盖总览

| 协议 | 类型 | ToP | Pure | Pairs | Direct |
|------|------|:---:|:----:|:-----:|:------:|
| VLESS | TLS+REALITY/XTLS | ✅ | ✅ | ✅ | — |
| Trojan | TLS | ✅ | ✅ | ✅ | — |
| Shadowsocks | 加密 SOCKS | ✅ | ✅ | ✅ | — |
| Hysteria2 | QUIC | ✅ | ✅ | ✅ | — |
| Mieru | 加密隧道 | ✅ | ✅ | ✅ | — |
| VMess | WebSocket | ✅ | ✅ | ✅ | — |
| AnyTLS | TLS | ✅ | ✅ | ✅ | — |
| NonTor | 直连 HTTP | — | — | — | ✅ |

---

## 六、最终统计

```
Tor_over_Proxy    70,000 PCAPs    (7 协议 × 10,000)
Pure_Proxy        70,000 PCAPs    (7 协议 × 10,000)
Tor_Direct        10,000 PCAPs    (NonTor)
Traffic_Pairs    140,000 PCAPs    (7 协议 × 10,000 对 × 2 方向)
─────────────────────────────────
总计             290,000 PCAPs
```

- **网站来源**: Tranco Top 1,000（每站点最多 10 个 PCAP）
- **PCAP 命名**: `output/<protocol>/<domain>/<NNN>.pcap`
- **容器架构**: Xray/Clash → Tor(可选) → tcpdump(eth0/lo) → Python 爬虫
- **容灾机制**: 多入站端口轮换 + obfs4 网桥绕过机场 DPI
- **自动停止**: `TARGET_TOTAL=10000` 达到后容器自动退出
