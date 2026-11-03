# 2026-10-28 Recapture — 数据构成详解

生成时间：2026-11-01（初稿）；完成独立校验与补充：2026-11-01  
数据截止：最后一次 `finalize.py` 为 2026-10-31 20:08；此后没有新增抓取。  
数据根目录：`g:\Tor_Crawl\2026-10-28_Recapture\`  
精简速查版：[PCAP_PROTOCOL_MAP.md](PCAP_PROTOCOL_MAP.md)（只看 PCAP 分类与数量）

---

## 1. 总览

| 指标 | 数值 |
|---|---:|
| 有效单元（unit） | **57,872** |
| PCAP 文件 | **78,899** |
| 总大小 | **19,923,317,763 bytes / 18.56 GiB** |
| 全局唯一域名 | **1,252**（跨模式去重） |
| 采集尝试（slot attempt） | 66,727（各任务最后一次运行计数，部分恢复后重置） |
| 单元/尝试计数比 | 86.73%（非严格成功率，见 §7.3） |
| 排除的 Mieru 文件 | 78 个 / 19.5 MiB（不计入以上） |
| 活动容器 | 0（全部停止） |

“单元”定义：

- Pure / ToP / NonTor：1 个 PCAP = 1 个单元。
- Traffic_Pairs：1 个 `_pre.pcap` + 1 个 `_post.pcap` = 1 对 = 1 个单元；
  因此 Pairs 的文件数是单元数的 2 倍。

> `attempts` 是任务最后一次运行的尝试计数。部分任务在补抓/恢复时重置了计数器
> （如 Pure VMess、NonTor），因此其 `units/attempts` 会大于 100%；该比例只作
> 整体参考，不是单次请求成功率。逐任务数据见 §4.5。

### 1.1 按模式汇总

| 模式 | 单元 | 文件 | 大小 MiB | 大小 GiB | 单元占比 | 文件占比 | 说明 |
|---|---:|---:|---:|---:|---:|---:|---|
| Pure_Proxy | 30,505 | 30,505 | 9,259.2 | 9.04 | 52.71% | 38.66% | 六协议全部达标 |
| Tor_over_Proxy | 1,340 | 1,340 | 678.0 | 0.66 | 2.32% | 1.70% | 部分数据，已停止 |
| Traffic_Pairs | 21,027 | 42,054 | 7,782.3 | 7.60 | 36.34% | 53.30% | 四协议满 5,000，两协议部分 |
| Tor_Direct/NonTor | 5,000 | 5,000 | 1,280.8 | 1.25 | 8.64% | 6.34% | 直连基线，达标 |
| **合计** | **57,872** | **78,899** | **19,000.3** | **18.56** | **100%** | **100%** | |

### 1.2 按协议跨模式汇总

| 协议 | 单元 | 文件 | 大小 MiB | 大小 GiB | 备注 |
|---|---:|---:|---:|---:|---|
| VLESS | 10,291 | 15,371 | 3,894.0 | 3.80 | Pure 5,000 + Pairs 5,080 + ToP 211 |
| AnyTLS | 5,988 | 6,537 | 2,487.6 | 2.43 | Pure 5,000 + Pairs 549 + ToP 439 |
| Hysteria2 | 5,472 | 5,730 | 3,016.5 | 2.95 | Pure 5,000 + Pairs 258 + ToP 214 |
| Trojan | 10,485 | 15,525 | 2,843.4 | 2.78 | Pure 5,289 + Pairs 5,040 + ToP 156 |
| Shadowsocks | 10,459 | 15,519 | 2,849.6 | 2.78 | Pure 5,216 + Pairs 5,060 + ToP 183 |
| VMess | 10,177 | 15,217 | 2,628.4 | 2.57 | Pure 5,000 + Pairs 5,040 + ToP 137 |
| NonTor | 5,000 | 5,000 | 1,280.8 | 1.25 | 直连基线 |

> Pairs 的“文件”为 pre/post 双文件；其余模式文件数等于单元数。

---

## 2. 目录结构与命名

```
2026-10-28_Recapture/
├── Pure_Proxy/<protocol>/<domain>/<NNN>.pcap
├── Tor_over_Proxy/<protocol>/<domain>/<NNN>.pcap
├── Traffic_Pairs/<protocol>/<domain>/<NNN>_pre.pcap
│                                   <NNN>_post.pcap
├── Tor_Direct/NonTor/<domain>/<NNN>.pcap
├── _pilot/                   # 已验证的试抓样本（不计入最终统计）
├── _preflight/               # 节点清单、测试结果、运行配置、可达站点列表
├── _meta/                    # 日志、进度、JSONL 元数据、失败记录
├── _excluded_mieru/          # 用户排除的 Mieru 数据与 mita 工具（不计入）
├── MANIFEST.csv              # 78,899 行，一行一个 PCAP
├── COUNTS.json               # 机器可读统计
├── FINAL_REPORT.md           # 最终统计表
├── DATA_COMPOSITION.md       # 本文档
├── README.md
├── STATUS.md
├── RESUMED.md
└── PAUSED_20261030.md（归档在 _meta/）
```

命名规则：

- `protocol`：`vless`、`anytls`、`hysteria2`、`trojan`、`ss`、`vmess`。
- `domain`：原始域名的文件名安全化版本（替换 `<>:"/\\|?*`，截断到 200 字符）。
- `NNN`：三位十进制序号，从 `001` 开始；每个域名最多 5–20 个，按采集阶段不同。
- Pairs 的 `_pre` 为代理封装前视角，`_post` 为代理封装后视角；两者同序号配对。
- 旧顶层 `Pure_Proxy/`、`Tor_over_Proxy/`、`Traffic_Pairs/`、`Tor_Direct/`
  **没有被修改**，不属于本数据集。

---

## 3. 采集模式与网络拓扑

### 3.1 Pure_Proxy（无 Tor）

**公开节点（VLESS / AnyTLS / Hysteria2）**

```
crawler → mihomo SOCKS(127.0.0.1:7890) → 公网代理节点 → 目标网站
                    │
                    └── tcpdump eth0（真实代理协议流量）
```

**自建前置（Trojan / SS / VMess）**

```
crawler → mihomo SOCKS(7890) → local Xray server → 目标
                    │                  │
                    │                  ├─ 172.31.0.10 + Hysteria2 上游（早期阶段）
                    │                  └─ 172.31.0.21 + freedom 直连（最终阶段）
                    └── tcpdump eth0（本地前置协议流量）
```

- 自建 Xray 监听：Trojan 8443（TLS）、SS 8388、VLESS 8444、VMess 8445。
- 自建阶段的 post 端点是 Docker 内网地址 `172.31.0.20/21`；
  `pcap_validate.py` 通过 `allowed_endpoints` 将这些私有端点视为合法代理端点。
- 标记仍是真实线协议（Trojan/SS/VMess），不是 SOCKS。

### 3.2 Tor_over_Proxy（ToP，部分）

```
crawler → Tor SOCKS(9050) → mihomo SOCKS(7890) → 公网代理节点
        → Tor 网络 → 目标
```

- 抓取点：容器 eth0，看到的是代理协议封装后的 Tor 流量。
- 公网阶段使用用户提供的 obfs4 网桥；后期出口阻断，任务按用户要求停止。

### 3.3 Traffic_Pairs（双视角，四协议已达标）

**WebTunnel 阶段（VLESS / Trojan / SS / VMess）**

```
crawler → Tor(9050) → mihomo local front(7890) ──lo:7890──> _pre.pcap
                         │
                         └→ local Xray direct server(172.31.0.21)
                              → WebTunnel HTTPS/WebSocket
                              → Tor 网络 → 目标
                              └── eth0──> _post.pcap
```

- `_pre`：`lo` 接口，`tcp and port 7890`，Tor 到本地 mihomo 的 SOCKS 流量。
- `_post`：容器 `eth0`，本地前置协议到 Xray direct server 的流量。
- WebTunnel 连接再经 Xray direct server 直连到 WebTunnel URL；
  Tor 的目标访问仍由 Tor 网络完成。
- 四协议每对均通过 HTTP + pre/post 双 PCAP 校验。

**公开节点 + obfs4 阶段（AnyTLS / Hysteria2，部分）**

```
crawler → Tor(9050) → mihomo(7890) → 公网 AnyTLS/Hysteria2 节点
        → Tor 网络 → 目标
```

- 产生 549 / 258 对；之后 obfs4 出口被阻断，未能继续。

### 3.4 Tor_Direct/NonTor（真直连）

```
crawler → 目标网站
              │
              └── tcpdump eth0（TCP / HTTP(S)，无代理）
```

- 只保留直连可达站点（804 个预筛域名中的 618 个实际成功域名）。
- 不经过 Tor、不经代理；与 Pure_Proxy 不是同一类数据。

### 3.5 抓包参数

| 模式 | 接口 | BPF 过滤 |
|---|---|---|
| Pure/ToP post | `eth0` | `not port 53 and (tcp or udp)` |
| Pairs pre | `lo` | `tcp and port 7890` |
| Pairs post | `eth0` | `not port 53 and (tcp or udp)` |
| NonTor | `eth0` | `tcp and not port 53` |

- 每个 HTTP 请求单独启动/停止一次 tcpdump，不是连续抓包。
- `-s 0` 全包长、`-U` 逐包 flush、`-n` 不解析主机名。
- PCAP 为 classic pcap（非 pcapng），以太网链路类型。
- 每日志与进度文件见 `_meta/`。

---

## 4. 逐模式/逐协议详细数量

> 大小单位：MiB/KiB 按 1024 进制；平均/中位/max 为单个 PCAP 文件大小。
> Pairs 的“单元”=一对，文件数=2×单元数；平均文件大小是单个 pre 或 post 的大小。

### 4.1 Pure_Proxy

| 协议 | 单元 | 文件 | 域名 | 大小 MiB | 平均文件 KiB | 中位文件 KiB | 最大文件 MiB | 目标 | 达成 | 尝试 | 站点 | 单元/域名 | 时间范围 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| VLESS | 5,000 | 5,000 | 627 | 2,054.8 | 420.8 | 251.0 | 2.44 | 5,000 | 100.0% | 5,022 | 629/728 | 7.97 | 10-28 18:17 → 10-29 00:17 |
| AnyTLS | 5,000 | 5,000 | 558 | 1,848.5 | 378.6 | 242.9 | 4.26 | 5,000 | 100.0% | 5,016 | 560/663 | 8.96 | 10-28 18:17 → 10-29 06:22 |
| Hysteria2 | 5,000 | 5,000 | 626 | 2,501.9 | 512.4 | 257.4 | 4.80 | 5,000 | 100.0% | 5,015 | 628/716 | 7.99 | 10-28 18:17 → 10-29 00:39 |
| Trojan | 5,289 | 5,289 | 551 | 1,074.6 | 208.1 | 218.2 | 1.43 | 5,000 | 105.8% | 5,116 | 664/804 | 9.60 | 10-28 18:18 → 10-30 08:32 |
| SS | 5,216 | 5,216 | 542 | 977.4 | 191.9 | 206.8 | 0.43 | 5,000 | 104.3% | 5,356 | 676/804 | 9.62 | 10-29 10:38 → 10-30 08:48 |
| VMess | 5,000 | 5,000 | 448 | 802.0 | 164.3 | 154.9 | 0.37 | 5,000 | 100.0% | 1,107 | 182/924 | 11.16 | 10-29 10:49 → 10-31 20:06 |

Pure 小计：**30,505 单元 / 30,505 文件 / 9,259.2 MiB**。  
说明：VLESS/AnyTLS/Hysteria2 经公开节点；Trojan/SS/VMess 经自建 Xray 前置；
VMess 使用 `vmess_refill.txt`（已知成功域名，每站上限 20）补到 5,000。

### 4.2 Tor_over_Proxy（部分，已停止）

| 协议 | 单元 | 文件 | 域名 | 大小 MiB | 平均文件 KiB | 中位文件 KiB | 最大文件 MiB | 目标 | 达成 | 尝试 | 站点 | 单元/域名 | 时间范围 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| AnyTLS | 439 | 439 | 44 | 172.5 | 402.5 | 255.4 | 2.46 | 5,000 | 8.8% | 1,239 | 310/1000 | 9.98 | 10-29 10:23 → 15:07 |
| Hysteria2 | 214 | 214 | 24 | 185.7 | 888.7 | 542.7 | 4.58 | 5,000 | 4.3% | 1,117 | 320/1000 | 8.92 | 10-29 10:22 → 11:36 |
| SS | 183 | 183 | 19 | 81.5 | 455.8 | 442.2 | 1.41 | 5,000 | 3.7% | 1,066 | 312/1000 | 9.63 | 10-29 10:51 → 11:36 |
| Trojan | 156 | 156 | 16 | 73.2 | 480.7 | 458.1 | 1.48 | 5,000 | 3.1% | 1,038 | 309/1000 | 9.75 | 10-29 10:43 → 11:36 |
| VLESS | 211 | 211 | 22 | 92.1 | 447.2 | 353.8 | 1.69 | 5,000 | 4.2% | 1,109 | 320/1000 | 9.59 | 10-29 10:43 → 11:36 |
| VMess | 137 | 137 | 14 | 72.9 | 545.1 | 510.2 | 1.88 | 5,000 | 2.7% | 1,019 | 306/1000 | 9.79 | 10-29 10:50 → 11:36 |

ToP 小计：**1,340 单元 / 1,340 文件 / 678.0 MiB**。  
说明：由公网节点 + 用户 obfs4 网桥产生；因机场出口阻断，后续停止。

### 4.3 Traffic_Pairs

| 协议 | 单元（对） | 文件 | 域名 | 大小 MiB | 平均文件 KiB | 中位文件 KiB | 最大文件 MiB | 目标 | 达成 | 尝试 | 站点 | 单元/域名 | 时间范围 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| AnyTLS | 549 | 1,098 | 57 | 466.6 | 435.1 | 333.4 | 1.73 | 5,000 | 11.0% | 1,310 | 307/1000 | 9.63 | 10-29 10:22 → 16:51 |
| Hysteria2 | 258 | 516 | 27 | 329.0 | 652.9 | 411.3 | 4.74 | 5,000 | 5.2% | 1,144 | 320/1000 | 9.56 | 10-29 10:22 → 11:36 |
| SS | 5,060 | 10,120 | 511 | 1,790.7 | 181.2 | 66.7 | 1.71 | 5,000 | 101.2% | 7,793 | 2,293/5000 | 9.90 | 10-29 10:49 → 10-31 17:56 |
| Trojan | 5,040 | 10,080 | 509 | 1,695.5 | 172.2 | 63.4 | 1.66 | 5,000 | 100.8% | 7,718 | 2,258/5000 | 9.90 | 10-29 10:44 → 10-31 17:35 |
| VLESS | 5,080 | 10,160 | 513 | 1,747.2 | 176.1 | 66.0 | 1.75 | 5,000 | 101.6% | 7,634 | 2,248/5000 | 9.90 | 10-29 10:43 → 10-31 17:20 |
| VMess | 5,040 | 10,080 | 506 | 1,753.5 | 178.1 | 65.4 | 2.30 | 5,000 | 100.8% | 7,635 | 2,228/5000 | 9.96 | 10-29 10:49 → 10-31 17:07 |

Pairs 小计：**21,027 对 / 42,054 文件 / 7,782.3 MiB**。  
说明：AnyTLS/Hysteria2 为公网节点 + obfs4 的早期部分；VLESS/Trojan/SS/VMess
为 WebTunnel 阶段，达到 5,000 对目标。目录内单元略高于 5,000，是因为旧阶段
已存在相同域名的有效文件；目标只统计本阶段站点列表内的采集。

### 4.4 Tor_Direct/NonTor

| 协议 | 单元 | 文件 | 域名 | 大小 MiB | 平均文件 KiB | 中位文件 KiB | 最大文件 MiB | 目标 | 达成 | 尝试 | 站点 | 单元/域名 | 时间范围 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| NonTor | 5,000 | 5,000 | 618 | 1,280.8 | 262.3 | 205.8 | 0.70 | 5,000 | 100.0% | 273 | 109/804 | 8.09 | 10-28 18:18 → 10-29 13:41 |

说明：直连可达性预筛 804 个域名，实际成功 618 个；主跑 4,826 条后用
直连可达列表补抓至 5,000。

### 4.5 逐任务效率、时长与停止原因

> “耗时”为首末文件 mtime 的墙钟跨度，包含暂停、重试和分阶段间隔，不是纯采集时间。
> “平均单元大小”：Pairs 为一对 `_pre` + `_post` 合计，其余为单个 PCAP。
> `target` 表示达到目标主动停止；`—` 表示被外部停止（网络不可用或手动停止），
> 不是达到目标。

| 模式/协议 | 单元 | 尝试 | units/attempts | 耗时(h) | 单元/小时 | 平均单元 KiB | 停止原因 |
|---|---:|---:|---:|---:|---:|---:|---|
| pure/anytls | 5,000 | 5,016 | 99.7% | 12.08 | 413.8 | 378.6 | target |
| pure/hysteria2 | 5,000 | 5,015 | 99.7% | 6.37 | 785.3 | 512.4 | target |
| pure/ss | 5,216 | 5,356 | 97.4% | 22.17 | 235.3 | 191.9 | target |
| pure/trojan | 5,289 | 5,116 | 103.4%* | 38.23 | 138.3 | 208.1 | target |
| pure/vless | 5,000 | 5,022 | 99.6% | 6.00 | 833.3 | 420.8 | target |
| pure/vmess | 5,000 | 1,107 | 451.7%* | 57.28 | 87.3 | 164.3 | target |
| top/anytls | 439 | 1,239 | 35.4% | 4.73 | 92.7 | 402.5 | — |
| top/hysteria2 | 214 | 1,117 | 19.2% | 1.23 | 173.5 | 888.7 | — |
| top/ss | 183 | 1,066 | 17.2% | 0.75 | 244.0 | 455.8 | — |
| top/trojan | 156 | 1,038 | 15.0% | 0.88 | 176.6 | 480.7 | — |
| top/vless | 211 | 1,109 | 19.0% | 0.88 | 238.9 | 447.2 | — |
| top/vmess | 137 | 1,019 | 13.4% | 0.77 | 178.7 | 545.1 | — |
| pairs/anytls | 549 | 1,310 | 41.9% | 6.48 | 84.7 | 870.3 | — |
| pairs/hysteria2 | 258 | 1,144 | 22.6% | 1.23 | 209.2 | 1,305.7 | — |
| pairs/ss | 5,060 | 7,793 | 64.9% | 55.12 | 91.8 | 362.4 | target |
| pairs/trojan | 5,040 | 7,718 | 65.3% | 54.85 | 91.9 | 344.5 | target |
| pairs/vless | 5,080 | 7,634 | 66.5% | 54.62 | 93.0 | 352.2 | target |
| pairs/vmess | 5,040 | 7,635 | 66.0% | 54.30 | 92.8 | 356.3 | target |
| nontor/NonTor | 5,000 | 273 | 1831.5%* | 19.38 | 258.0 | 262.3 | target |

\* 超过 100% 的计数比来自跨阶段累计的已有文件和恢复后重置的 `attempts`，
不代表实际请求成功率；说明见 §7.3。

---

## 5. 文件大小分布（整个数据集）

| 统计量 | 字节 | 人类可读 |
|---|---:|---:|
| 最小 | 2,219 | 2.17 KiB |
| 中位 | 153,463 | 149.9 KiB |
| 平均 | 252,517 | 246.6 KiB |
| P90 | 596,060 | 582.1 KiB |
| P99 | 1,742,688 | 1.66 MiB |
| 最大 | 5,033,287 | 4.80 MiB |

- 小文件通常来自短页面、204/重定向或小响应；仍经过完整 HTTP + 双向载荷校验。
- Pairs 的每个单元包含 pre/post 两个文件，平均单元大小约为单文件中位数的 2 倍。

---

## 6. 域名构成

- 全局唯一域名：**1,252**。
- 各模式唯一域名：Pure **775**、ToP **46**、Pairs **583**、NonTor **618**。
  各模式之间 / 各协议之间存在重叠，因此分模式相加会大于全局数。
- 每个协议的域名数见上表。

文件数最多的域名（跨模式累计，含 Pairs 的 pre/post）：

| 域名 | 文件数 |
|---|---:|
| apple.com | 255 |
| amazon.com | 245 |
| bit.ly | 245 |
| microsoft.com | 245 |
| wordpress.com | 245 |
| youtu.be | 243 |
| google.com | 238 |
| github.com | 235 |
| instagram.com | 229 |
| pinterest.com | 229 |
| wikipedia.org | 229 |
| youtube.com | 229 |
| mozilla.org | 225 |
| blogspot.com | 221 |
| qq.com | 215 |
| twitter.com | 210 |
| gravatar.com | 199 |
| wordpress.org | 195 |
| amazonaws.com | 194 |
| t.co | 179 |

注意：域名计数受每站上限、模式数和目标数共同影响，不代表站点真实流量排名。

---

## 7. 数据验证与有效性

### 7.1 保留条件

一个 PCAP 只有同时满足以下条件才保留：

1. HTTP/HTTPS 状态码为 **200–399**（4xx/5xx 不保存）。
2. PCAP 中存在到合法代理端点的双向传输载荷：
   - TCP：客户端→服务端、服务端→客户端均有 payload；
   - Hysteria2：UDP 双向包和字节数达标，且 HTTP 成功；
   - Pairs 的 pre/post 两端都必须通过。
3. 远端端点匹配所选节点端口/端口范围，或匹配自建服务器的
   `allowed_endpoints`（`172.31.0.20/21:port`）。
4. 不包含宿主机 Clash 的 `192.168.65.254:7897` 流量。
5. 不存在“数据前 RST”。
6. PCAP 文件至少 500 字节；实际最小保存文件为 2,219 字节。

对于长连接（Tor 到 mihomo、代理复用连接），不强制要求捕获窗口内出现 SYN；
以双向 payload 作为通信成功的证据。NonTor 仍要求完整 TCP 三次握手。

### 7.2 校验器

校验器：`docker/recapture/pcap_validate.py`

- 解析 classic pcap / Ethernet / SLL / SLL2 / loopback / raw IP；
- 解析 IPv4/IPv6、TCP/UDP、TCP flags、payload、端点、QUIC long header；
- 支持 `allowed_ports`、`allowed_endpoints`、`pre`/`post`/`nontor` 模式；
- 返回 `valid`、`reasons` 和完整计数摘要。

### 7.3 失败处理

- 无效 PCAP 在重命名前即删除，不会进入正式目录。
- 失败记录写入 `_meta/<job>_failures.jsonl`，共约 **41,862** 条记录。
- 这里的记录是“每次方案/重试”级别，数量大于“有效单元差”。
- 采集尝试（slot attempt）合计 66,727，有效单元 57,872，计数比为 86.73%。
  该比例**不是严格成功率**：部分任务在补抓/恢复时重置了 attempts，例如：
  - Pure VMess 的 5,000 个单元中有 4,196 个是上一轮已有文件，恢复后
    attempts 只统计新增的 1,107 次；
  - NonTor 主跑 4,826 条，之后用直连可达列表补抓，attempts 只统计
    补抓阶段的 273 次；
  - Pure Trojan 同样跨阶段累计，因此 units/attempts 显示为 103.4%。

  逐任务的计数比与耗时见 §4.5，不建议把它们当作统一的成功率指标。

### 7.4 每单元元数据

`_meta/<job>.jsonl` 每个成功单元包含：

```json
{
  "ts": "...",
  "job": "pairs__vless",
  "mode": "pairs",
  "protocol": "vless",
  "domain": "...",
  "index": 1,
  "site_slot": 0,
  "http": {"ok": true, "status": 200, "body_len": ..., "duration": ...},
  "scheme": "https",
  "node": "direct-vless",
  "pcap_bytes": ...,
  "validator_post": {"valid": true, "reasons": [], "summary": {...}},
  "validator_pre": {"valid": true, "reasons": [], "summary": {...}},
  "files": ["001_pre.pcap", "001_post.pcap"]
}
```

`_meta/progress/*.json` 记录 captured/target/attempts/sites/current_node/stop_reason；
`_meta/logs/` 保存容器日志；`_meta/*_failures.jsonl` 保存失败原因。

- `_meta/<job>.jsonl` 的行数大体等于最终单元数；个别任务多出 2–4 行，
  均为 `example.com` / `www.baidu.com` 的测试记录（文件未保留）或同序号
  重复尝试记录。每个最终单元（Pairs 为一对两个文件）均可在 `_meta` 中找到
  对应记录（缺失数为 0），统计与分发请以 `MANIFEST.csv` 为准。

---

## 8. 节点与基础设施

### 8.1 节点来源与规模

去重后的候选节点清单：**1,465** 个（`_preflight/nodes_all.json`）：

| 协议 | 候选数 |
|---|---:|
| VLESS | 810 |
| SS | 258 |
| Trojan | 225 |
| AnyTLS | 100 |
| Hysteria2 | 62 |
| Mieru | 10（已排除） |

来源明细（profile/subscription 级，去重前）：

| 来源 | 协议与数量 | 备注 |
|---|---|---|
| Clash Verge / CNIX | 180 VLESS | 当时 active profile |
| Clash Verge / 西游云 | 48 AnyTLS + 2 Trojan + 1 SS + 1 TUIC | TUIC 不参与 |
| Clash Verge / 山海 ShanHai | 4 VLESS + 29 AnyTLS | |
| Clash Verge / SS-ID | 15 SS | 公网 SS 测试全部失败 |
| Clash Verge / 狗狗 | 4 SS | 多为占位/失效节点 |
| Clash Verge / 本地 1.yaml | 45 SS + 26 VLESS | |
| Doggy 订阅（mihomo UA） | 23 Hysteria2 + 10 Mieru + 27 AnyTLS + 1 占位 VMess | Mieru 后排除 |
| 用户 batch2 URI | VIP88 的 VLESS xhttp/ML-KEM、AnyTLS、Hysteria2 | VLESS xhttp 在 mihomo 中握手失败 |
| `proxy_nodes.md` 免费列表 | 251 SS / 386 Trojan / 886 VLESS / 332 VMess | VMess 跳过；大量为过期节点 |
| 手动补充 | 3 个用户 Trojan + 自有 Trojan + 5 个 SSIDWork SS 端口 | |

经过解析、失效过滤和去重后，最终候选 **1,465** 个。

公共节点与自建节点的最终分工：

- Pure VLESS/AnyTLS/Hysteria2：公网节点（分别使用 17 / 7 / 17 个候选中的可用节点）。
- Pure Trojan/SS/VMess：自建 Xray 前置 + 直连/上游，不再依赖公网节点。
- Pairs VLESS/Trojan/SS/VMess：WebTunnel + 本地直连前置。
- Pairs AnyTLS/Hysteria2：公网节点 + obfs4（部分）。
- ToP：公网节点 + obfs4（部分，已停止）。

### 8.2 节点测试结果

测试方式：mihomo 真实握手 + 控制器 per-proxy delay；目标为
Cloudflare/gstatic/百度 HTTP 请求。

| 协议 | 测试数 | 可用 | 说明 |
|---|---:|---:|---|
| VLESS | 214 | 17 | 免费 VLESS 列表加入后未全部重测；选中的 17 个来自 CNIX 等 |
| SS | 258 | 0 | 公网 SS 全部失败；后来自建 Xray SS 解决 |
| Trojan | 225 | 8 | 含自有节点和免费 Trojan |
| AnyTLS | 100 | 7 | 用户 batch2 VIP88 AnyTLS |
| Hysteria2 | 62 | 36 | 用户 batch2 VIP88 Hysteria2 |
| Mieru | 10 | 0 | 已排除 |

### 8.3 站点可达性预筛（每协议 1,000 域名）

| 协议 | 可达 | HTTPS | HTTP |
|---|---:|---:|---:|
| VLESS | 728 | 694 | 34 |
| AnyTLS | 663 | 438 | 225 |
| Hysteria2 | 716 | 690 | 26 |
| Trojan | 84 | 60 | 24 |
| 直连（NonTor 预筛） | 804 | 797 | 7 |

### 8.4 Tor / 网桥

- 普通 Tor：对 4 协议各 6 个候选（共 24 个）测试，全部卡在 10% TLS；
  自有 Trojan 节点同样失败。
- obfs4：用户提供多批网桥，新/旧网桥 TCP 可达，但机场出口在数据层阻断；
  Tor 卡在 2%。
- meek_lite：到达 10%，CDN 前置返回 EOF。
- Snowflake：broker EOF，STUN/UDP 超时。
- **WebTunnel：成功**。直连和经 CNIX VLESS 都能 Bootstrap 100%，
  IsTor=true，example 200；最终 Pairs 采用本地直连前置 + WebTunnel。
- 使用的 WebTunnel 入口（路径 token 已隐去）：
  - `web.localenby.is`
  - `bridge.64-83-2-102.sslip.io:8443`
- 最终 Pairs 拓扑因此改为：
  Tor + WebTunnel → mihomo 本地前置 → Xray direct server → WebTunnel URL。

### 8.5 自建服务

- Xray 26.3.27：Trojan 8443(TLS)、SS 8388、VLESS 8444、VMess 8445。
- 早期上游：Hysteria2 节点 `hy0030`（通过本地 mihomo SOCKS 转发）；
  最终 Pure Trojan/SS/VMess 及 WebTunnel Pairs 使用直连 Xray 服务器。
- mihomo 1.19.29（客户端/前置）；Tor 0.4.9.11；lyrebird（Tor expert
  bundle 15.0.26）用于 WebTunnel。
- Docker 28.3.0、Python 3.11、pysocks、tcpdump。

---

## 9. 站点列表

| 文件 | 用途 |
|---|---|
| `docker/configs/top1000.txt` | Tranco Top 1000；Pure/ToP/NonTor 的基础站点列表 |
| `docker/recapture/top5000.txt` | Umbrella Top 5000（前 5,000 行）；WebTunnel Pairs 扩展列表 |
| `_preflight/direct_reachable.txt` | 直连预筛通过的 804 个域名；NonTor/Pure 直连补抓 |
| `_preflight/reachable_vless.txt` | 728 个 VLESS 可访问域名 |
| `_preflight/reachable_anytls.txt` | 663 个 AnyTLS 可访问域名 |
| `_preflight/reachable_hysteria2.txt` | 716 个 Hysteria2 可访问域名 |
| `_preflight/reachable_trojan.txt` | 84 个 Trojan 可访问域名 |
| `_preflight/vmess_refill.txt` | 924 个已验证成功/可达域名；VMess 最终补抓 |

每站上限（按阶段）：

- Pure 公开节点：VLESS 8、AnyTLS 9、Hysteria2 8。
- Pure 自建/直连：Trojan 10、SS 10、VMess 20（refill）。
- ToP / Pairs：10。
- NonTor：8（主跑）/ 10（top-up）。
- 目标均为每协议 5,000 个有效单元。

---

## 10. 时间线

| 时间 | 事件 |
|---|---|
| 2026-10-28 18:17 | 主阶段启动：Pure VLESS/AnyTLS/Hysteria2、NonTor、公开节点 ToP/Pairs 部分 |
| 2026-10-28 18:18 | 首批 PCAP 落盘 |
| 2026-10-29 00:17 | Pure VLESS 达到 5,000 |
| 2026-10-29 00:39 | Pure Hysteria2 达到 5,000 |
| 2026-10-29 06:22 | Pure AnyTLS 达到 5,000 |
| 2026-10-29 10:38 | 自建 Xray 前置启动（Trojan/SS） |
| 2026-10-29 10:43–11:36 | 公开节点 + obfs4 的 ToP/Pairs 部分数据；随后停止 ToP |
| 2026-10-29 12:33 | 主监督器结束 |
| 2026-10-29 13:41 | NonTor 最后一条数据 |
| 2026-10-29 15:36 | Trojan/SS 直连补抓启动 |
| 2026-10-30 08:32/08:48 | Pure Trojan / SS 直连达标 |
| 2026-10-30 15:52 | 用户按网络使用需求暂停，所有容器停止 |
| 2026-10-30 16:54 | 恢复；WebTunnel 复测 100% 后重启 Pairs |
| 2026-10-31 17:56 | 四个 WebTunnel Pairs 全部达到 5,000 对 |
| 2026-10-31 20:06 | Pure VMess 补到 5,000 |
| 2026-10-31 20:08 | 生成最终 MANIFEST / COUNTS / FINAL_REPORT |
| 2026-11-01 00:02 | 复核：无活动容器，数据未变化 |
| 2026-11-01 00:08 | `DATA_COMPOSITION.md` 初稿生成 |
| 2026-11-01 00:24 | 完成数据一致性校验，补充 §4.5 / §7.3 / §7.4 / §11.1 / §16 |

---

## 11. 文件与产物说明

- `MANIFEST.csv`：78,899 行 + 表头；列为
  `mode,protocol,domain,file,bytes`；一个文件一行，Pairs 的 pre/post 各一行。
- `COUNTS.json`：总单元/文件/字节，逐任务 units/files/domains/bytes/target/attempts/sites/stop。
- `FINAL_REPORT.md`：最终统计表、验证说明、被排除项。
- `_preflight/`：节点清单、节点测试结果、订阅/URI 归档（含敏感凭据，请勿外传）、
  mihomo 运行配置、站点可达列表。
- `_pilot/`：各协议的试抓样本；不参与最终统计，但用于人工验证。
- `_excluded_mieru/`：78 个 Mieru PCAP（19.5 MiB）与 mita 工具/配置；
  用户已明确排除，不进入 MANIFEST。
- `PAUSED_20261030.md`：暂停记录；`RESUMED.md`：恢复记录。
- 旧的顶层四个目录：未改动，不属于本数据集。
- 目录体积（约）：`_meta/` 117 MiB、`_preflight/` 49 MiB、
  `_pilot/` 62 个 PCAP（3.4 MiB）、`_excluded_mieru/` 47 MiB
  （其中 78 个 PCAP 为 19.5 MiB，其余为 mita 工具/配置）。

### 11.1 校验和（SHA256，2026-11-01）

| 文件 | SHA256 |
|---|---|
| `MANIFEST.csv` | `e554afe5a3799eb3b4d71aed74f4421a2ff1706a094c06b9cafdd94471ca9721` |
| `COUNTS.json` | `6bd3bc30e67cca5fa7f3ece9c94144de82adf957b382ab44d1a9c226757689b8` |
| `FINAL_REPORT.md` | `c708a282310121748768d4bb6df40504ab4a8a9ece7c232e2e2659e95eb2b357` |

PCAP 本体未生成逐文件哈希。对外分发前建议在仓库根目录执行：

```bash
find 2026-10-28_Recapture -name '*.pcap' -print0 | xargs -0 sha256sum > SHA256SUMS.pcap
```

（约 19 GB，耗时较长。）

---

## 12. 已知限制与使用注意

1. **ToP 是部分数据**：因机场出口阻断，ToP 仅 1,340 单元，已停止；
   不可当作完整 ToP 数据集。
2. **AnyTLS/Hysteria2 Pairs 是部分数据**：549/258 对；没有可用的
   WebTunnel 路径，未继续。
3. **Mieru 已排除**：不要使用 `_excluded_mieru/` 作为正式数据。
4. **自建前置的 Pure Trojan/SS/VMess**：post 端点是本地 Docker 地址，
   不是公网代理服务器；线协议是真实的 Trojan/SS/VMess。
5. **WebTunnel Pairs 的视角**：`_pre` 是 Tor→mihomo SOCKS；`_post` 是
   本地前置协议→Xray direct server。Tor 目标流量在 Tor 网络内部，
   pre/post 不直接暴露目标 IP 或明文 HTTP。
6. **站点列表混合**：Pure/ToP/NonTor 基于 Tranco Top1000；WebTunnel Pairs
   扩展到 Umbrella Top5000。不同协议的域名覆盖不完全相同。
7. **HTTP body 有上限**（早期 2MB/512KB，后期 256KB），PCAP 可能不包含
   完整页面；但包含连接建立、请求和部分响应流量。
8. **每站样本数有限**（5–20），部分域名可能因目标限流/证书问题未达上限。
9. **MANIFEST 无哈希**：仅记录路径与字节数；对外分发前建议自行生成
   SHA256 清单。
10. **旧顶层数据可能包含错误标签**（旧 vless/anytls/hysteria2/mieru/NonTor
    实际是到宿主机 Clash 的 SOCKS 流量）；请只使用本目录新数据。

---

## 13. 复现与使用

### 13.1 数据结构读取

```python
import pandas as pd
m = pd.read_csv("2026-10-28_Recapture/MANIFEST.csv")
# Pure VLESS
pure_vless = m[(m["mode"] == "pure") & (m["protocol"] == "vless")]
# Pairs 只看 post
pairs_post = m[(m["mode"] == "pairs") & m["file"].str.endswith("_post.pcap")]
```

### 13.2 单文件检查

```bash
tshark -r "Pure_Proxy/vless/google.com/001.pcap" -q -z io,phs
tshark -r "Traffic_Pairs/vless/google.com/001_pre.pcap" -q -z io,phs
tshark -r "Traffic_Pairs/vless/google.com/001_post.pcap" -q -z io,phs
```

### 13.3 重新生成统计

```bash
python docker/recapture/finalize.py
```

### 13.4 恢复抓取（如需）

当前所有容器已停止。重新抓取前需启动本地直连前置
`rc-xray-direct`，并确认 WebTunnel 可达；入口脚本与配置在
`docker/recapture/`，具体命令见 `RESUMED.md`/`_meta/PAUSED_20261030.md`。

---

## 14. 主要脚本与版本

| 组件 | 版本/说明 |
|---|---|
| mihomo | v1.19.29 |
| Xray-core | 26.3.27 |
| Tor | 0.4.9.11 |
| lyrebird | Tor expert bundle 15.0.26（WebTunnel） |
| Python | 3.11 |
| tcpdump | Debian 容器内 |
| Docker | 28.3.0 |
| 校验器 | `docker/recapture/pcap_validate.py` |
| 爬虫 | `docker/recapture/capture.py` |
| 节点清单 | `docker/recapture/build_inventory.py` |
| 节点测试 | `docker/recapture/node_test.py`、`tor_test_all.py` |
| 运行配置 | `docker/recapture/make_runtime.py` |
| 监督器 | `docker/recapture/run_pairs_webtunnel_supervisor.py` 等 |
| 最终统计 | `docker/recapture/finalize.py` |

---

## 15. 结论

本轮重新抓取最终产出 **57,872 个有效单元 / 78,899 个 PCAP / 18.56 GiB**：

- Pure 六协议全部达到或超过 5,000；
- Pairs 的 VLESS/Trojan/SS/VMess 达到 5,000 对；
- NonTor 达到 5,000；
- ToP 与 AnyTLS/Hysteria2 Pairs 为部分数据；
- Mieru 已按用户要求排除。

旧顶层数据未改动；新数据、元数据和最终清单均位于
`2026-10-28_Recapture/`。

---

## 16. 一致性校验（2026-11-01）

初稿完成后，对 `MANIFEST.csv`、`COUNTS.json`、四个数据目录和 `_meta` 元数据
做了一次独立复核，结果如下：

| 校验项 | 期望 | 实测 | 结论 |
|---|---:|---:|---|
| MANIFEST 数据行 | 78,899 | 78,899 | ✅ |
| MANIFEST 总字节 | 19,923,317,763 | 19,923,317,763 | ✅ |
| COUNTS 总单元 / 文件 / 字节 | 57,872 / 78,899 / 19,923,317,763 | 相同 | ✅ |
| 四个数据目录 PCAP 总数 | 78,899 | 78,899 | ✅ |
| MANIFEST 路径与磁盘文件 | 双向一致 | 0 缺失 / 0 多余 | ✅ |
| 全局唯一域名 | 1,252 | 1,252 | ✅ |
| 各任务 attempts 合计 | 66,727 | 66,727 | ✅ |
| 失败日志行数 | 41,862 | 41,862 | ✅ |
| `_meta` 记录覆盖 MANIFEST | 全部单元 | 0 缺失 | ✅ |
| `_pilot` 样本 | — | 62 个 PCAP | ℹ️ 不计入统计 |
| `_excluded_mieru` | — | 78 个 PCAP / 20,424,510 B | ℹ️ 不计入统计 |
| 文件大小分位数 | 见 §5 | 一致 | ✅ |

复核命令（在仓库根目录 `g:\Tor_Crawl` 下运行）：

```bash
# 重新从 MANIFEST 汇总，核对行数、总字节与分位数
python - <<'PY'
import csv, statistics
rows = list(csv.DictReader(open('2026-10-28_Recapture/MANIFEST.csv', encoding='utf-8')))
sizes = sorted(int(r['bytes']) for r in rows)
print(len(rows), sum(sizes), sizes[0], int(statistics.median(sizes)), sizes[-1])
PY

# 核对 MANIFEST 与磁盘文件一一对应
python - <<'PY'
import csv, glob
from pathlib import Path
rows = list(csv.DictReader(open('2026-10-28_Recapture/MANIFEST.csv', encoding='utf-8')))
paths = {Path('2026-10-28_Recapture', r['file']).as_posix() for r in rows}
disk = {Path(p).as_posix() for pat in ('Pure_Proxy/**/*.pcap', 'Tor_over_Proxy/**/*.pcap',
        'Traffic_Pairs/**/*.pcap', 'Tor_Direct/NonTor/**/*.pcap')
        for p in glob.glob('2026-10-28_Recapture/' + pat, recursive=True)}
print(len(paths), len(disk), len(paths - disk), len(disk - paths))
PY

# 校验和
sha256sum 2026-10-28_Recapture/MANIFEST.csv \
          2026-10-28_Recapture/COUNTS.json \
          2026-10-28_Recapture/FINAL_REPORT.md
```

注意：重新运行 `docker/recapture/finalize.py` 会重写 `MANIFEST.csv`、
`COUNTS.json` 和 `FINAL_REPORT.md`；§11.1 的校验和对应 2026-10-31 20:08 版本。

（文档完）
