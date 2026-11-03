# PCAP 协议构成速查

数据根目录：`2026-10-28_Recapture/`  
统计来源：`MANIFEST.csv`（78,899 个 PCAP）  
详细版：[DATA_COMPOSITION.md](DATA_COMPOSITION.md)

## 1. 怎么判断一个 PCAP 属于哪种

看路径：

```
2026-10-28_Recapture/<模式目录>/<协议>/<域名>/<NNN>.pcap
```

| 路径部分 | 可选值 |
|---|---|
| 模式目录 | `Pure_Proxy`、`Tor_over_Proxy`、`Traffic_Pairs`、`Tor_Direct/NonTor` |
| 协议 | `vless`、`anytls`、`hysteria2`、`trojan`、`ss`、`vmess` |

- PCAP 里抓到的是**外层协议**；是否经过 Tor 由模式目录决定。
- `Traffic_Pairs` 的 `_pre.pcap` + `_post.pcap` 成对出现，一对算 1 个单元。
- `Tor_Direct/NonTor` 没有代理协议层，PCAP 就是普通 TCP/TLS。

例子：

| PCAP 路径示例 | 属于 | 该类 PCAP 数 |
|---|---|---:|
| `Pure_Proxy/vless/example.com/001.pcap` | Pure-VLESS（无 Tor） | 5,000 |
| `Tor_over_Proxy/vless/example.com/001.pcap` | ToP-VLESS | 211 |
| `Traffic_Pairs/vless/example.com/001_pre.pcap` | Pairs-VLESS 的 pre 视角 | 5,080 |
| `Traffic_Pairs/vless/example.com/001_post.pcap` | Pairs-VLESS 的 post 视角 | 5,080 |
| `Tor_Direct/NonTor/example.com/001.pcap` | NonTor 直连 | 5,000 |

## 2. 按模式分类的数量

### 2.1 Pure_Proxy（无 Tor）

| 协议 | PCAP 数 | PCAP 里是什么 |
|---|---:|---|
| VLESS | 5,000 | 到公网 VLESS 节点的 VLESS 协议流量 |
| AnyTLS | 5,000 | 到公网 AnyTLS 节点的 AnyTLS 协议流量 |
| Hysteria2 | 5,000 | 到公网 Hysteria2 节点的 Hysteria2 协议流量 |
| Trojan | 5,289 | 到本地自建 Xray 前置的 Trojan 协议流量 |
| SS | 5,216 | 到本地自建 Xray 前置的 Shadowsocks 协议流量 |
| VMess | 5,000 | 到本地自建 Xray 前置的 VMess 协议流量 |
| **小计** | **30,505** | 30,505 个单元 |

### 2.2 Tor_over_Proxy（ToP，共 6 种）

ToP 的 PCAP 都是 `eth0` 上的外层代理协议流量，里面封装着 Tor 流量：

| ToP 子类 | 路径 | PCAP 数 |
|---|---|---:|
| ToP-VLESS | `Tor_over_Proxy/vless/` | 211 |
| ToP-AnyTLS | `Tor_over_Proxy/anytls/` | 439 |
| ToP-Hysteria2 | `Tor_over_Proxy/hysteria2/` | 214 |
| ToP-Trojan | `Tor_over_Proxy/trojan/` | 156 |
| ToP-SS | `Tor_over_Proxy/ss/` | 183 |
| ToP-VMess | `Tor_over_Proxy/vmess/` | 137 |
| **小计** | | **1,340** |

### 2.3 Traffic_Pairs（双视角）

每对 = 1 个 `_pre.pcap` + 1 个 `_post.pcap`：

- `_pre`：`lo` 上 Tor → mihomo 的 SOCKS 流量（tcp/7890）。
- `_post`：`eth0` 上本地前置/公网节点的外层协议流量。

| 协议 | pre PCAP | post PCAP | 对数（单元） | post 抓的是什么 |
|---|---:|---:|---:|---|
| VLESS | 5,080 | 5,080 | 5,080 | 本地 Xray 前置的 VLESS（WebTunnel 路径） |
| AnyTLS | 549 | 549 | 549 | 公网 AnyTLS 节点 |
| Hysteria2 | 258 | 258 | 258 | 公网 Hysteria2 节点 |
| Trojan | 5,040 | 5,040 | 5,040 | 本地 Xray 前置的 Trojan（WebTunnel 路径） |
| SS | 5,060 | 5,060 | 5,060 | 本地 Xray 前置的 Shadowsocks（WebTunnel 路径） |
| VMess | 5,040 | 5,040 | 5,040 | 本地 Xray 前置的 VMess（WebTunnel 路径） |
| **小计** | **21,027** | **21,027** | **21,027** | **42,054 个 PCAP** |

AnyTLS / Hysteria2 为部分数据；其余四协议达到 5,000 对目标。

### 2.4 Tor_Direct/NonTor（真直连）

| 类别 | PCAP 数 | PCAP 里是什么 |
|---|---:|---|
| NonTor | 5,000 | `eth0` 上到目标的普通 TCP/TLS，无代理、无 Tor |

## 3. 总计

| 模式 | PCAP 数 | 单元数 |
|---|---:|---:|
| Pure_Proxy | 30,505 | 30,505 |
| Tor_over_Proxy | 1,340 | 1,340 |
| Traffic_Pairs | 42,054 | 21,027 |
| Tor_Direct/NonTor | 5,000 | 5,000 |
| **合计** | **78,899** | **57,872** |

## 4. 快速统计

```bash
# ToP 各协议各有多少 PCAP
find 2026-10-28_Recapture/Tor_over_Proxy -name '*.pcap' | cut -d/ -f3 | sort | uniq -c

# 任一模式同理
find 2026-10-28_Recapture/Pure_Proxy -name '*.pcap' | cut -d/ -f3 | sort | uniq -c
```
