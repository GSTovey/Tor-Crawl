# 2026-10-28 Recapture — 采集元数据索引

生成时间：2026-11-01  
对应数据集：`/mnt/data/zcx/dataset_2610/`  
PCAP 根目录：`/mnt/data/zcx/dataset_2610/pcap/`  
元数据根目录：`/mnt/data/zcx/dataset_2610/metadata/`  
本地原始根目录：`g:\Tor_Crawl\2026-10-28_Recapture\`、`g:\Tor_Crawl\docker\recapture\`

> 服务器检索结果：`/mnt/data/zcx`、`/home/das`、`/tmp` 下没有现成的
> `MANIFEST.csv`、`COUNTS.json`、`_meta/`、`_preflight/`。因此本次把本地完整
> 元数据同步到了 `metadata/`，并在其中保留了原始目录结构。

---

## 0. 结论速览

| 需求 | 状态 | 位置 / 说明 |
|---|---|---|
| 1. 完整元数据路径 | ✅ | `/mnt/data/zcx/dataset_2610/metadata/` |
| 2. 每 PCAP 的 task/pair/session/capture/condition/wrapper/transport/domain | ⚠️ 部分 | `metadata/capture_index.csv` 已生成；`session_id` 不是真实会话 ID，见 §2 |
| 3. 实际节点/服务器/客户端/配置哈希/时间窗 | ✅ | `NODE_MAP.csv` + `runtime/` + `config/` + `CONFIG_SHA256SUMS.txt`，见 §3 |
| 4. PCAP 内 5-tuple 映射 | ⚠️ 端点级已有，流级未落盘 | `_meta` 有 `remote_endpoints`/`local_endpoints`；完整 5-tuple 需用 `tshark` 提取，规则见 §4 |
| 5. Pure / ToP 是否同一任务/站点/配置/节点/条件 | ❌ 否 | 共用站点源；节点部分重叠；任务、配置、条件不同，见 §5 |
| 6. 是否有真实 `arrival_timestamp` | ❌ 没有 | PCAP 是本地抓包时间（µs），只能按 capture order replay，见 §6 |
| 7. D1–D4 划分 | ➖ 数据中没有既定划分 | 给出 mode-based 与 wrapper-based 两套可执行分组，见 §7 |

最小阻塞项 1–4 的落点：

- 第 1 项：`metadata/` 下全部文件；清单见 §1。
- 第 2 项：`metadata/capture_index.csv`（78,899 行/每 PCAP 一行）+ `_meta/`。
- 第 3 项：`metadata/NODE_MAP.csv` + `metadata/runtime/` + `metadata/config/` +
  `metadata/CONFIG_SHA256SUMS.txt` + §3 的时间窗表。
- 第 4 项：`_meta` 端点级摘要 + `tshark 4.0.17`（服务器已安装）+ §4 分类规则与样本。

---

## 1. 目录与路径

### 1.1 服务器路径

```
/mnt/data/zcx/dataset_2610/
├── CAPTURE_METADATA.md              # 本文档
├── PCAP_PROTOCOL_MAP.md
├── DATA_COMPOSITION.md
├── pcap/                            # 78,899 个 PCAP
│   ├── Pure_Proxy/{vless,anytls,hysteria2,trojan,ss,vmess}/...
│   ├── Tor_over_Proxy/{...}/...
│   ├── Traffic_Pairs/{...}/...
│   └── Tor_Direct/NonTor/...
└── metadata/
    ├── MANIFEST.csv                 # 78,899 行，一行一个 PCAP
    ├── COUNTS.json                  # 机器可读统计
    ├── FINAL_REPORT.md              # 原始最终报告
    ├── capture_index.csv            # 派生：每 PCAP 的采集索引（78,899 行）
    ├── NODE_MAP.csv                 # 派生：runtime 节点 → server:port / 配置哈希
    ├── CONFIG_SHA256SUMS.txt        # 配置与关键脚本的 SHA256
    ├── _meta/                       # 逐任务 JSONL、失败、进度、容器日志
    ├── _preflight/                  # 节点清单、节点/网桥测试、可达列表、订阅快照
    ├── runtime/                     # 27 个任务运行配置：mihomo.json + meta.json
    ├── config/
    │   ├── server/                  # Xray 服务端配置（不含私钥）
    │   ├── bridges_*.txt            # 网桥列表（obfs4/webtunnel 等）
    │   ├── torrc*.template          # Tor 模板
    │   ├── top1000.txt
    │   └── top5000.txt
    └── code/
        ├── build_capture_index.py   # 生成 capture_index.csv
        ├── capture.py
        ├── pcap_validate.py
        ├── run_job.py
        ├── make_runtime.py
        ├── finalize.py
        └── ...                      # 其余采集/测试脚本
```

### 1.2 本地原始路径

- 数据与元数据：`g:\Tor_Crawl\2026-10-28_Recapture\`
- 运行配置与代码：`g:\Tor_Crawl\docker\recapture\`
- 数据说明：`DATA_COMPOSITION.md`、`PCAP_PROTOCOL_MAP.md`

### 1.3 关键文件说明

| 文件/目录 | 内容 | 规模 |
|---|---|---:|
| `metadata/MANIFEST.csv` | `mode,protocol,domain,file,bytes` | 78,899 行 + 表头 |
| `metadata/COUNTS.json` | 总单元/文件/字节，逐任务统计 | 5,943 B |
| `metadata/capture_index.csv` | 每 PCAP 的派生采集字段 | 78,899 行，约 23 MB |
| `metadata/NODE_MAP.csv` | runtime → 节点 → server:port → 配置 SHA256 | 72 行 |
| `metadata/_meta/` | 19 个任务的 JSONL + failures + progress + logs | 121,928,937 B |
| `metadata/_preflight/` | 节点/网桥/可达性/订阅/测试配置 | 50,093,891 B |
| `metadata/runtime/` | 27 个 `mihomo.json` + `meta.json` | 约 125 KB |
| `metadata/config/server/` | `config.json`、`config-direct.json`、`upstream-hy2.json` | 约 5 KB |

> `_preflight/subscriptions/`、`_preflight/nodes_all.json`、`_preflight/test_configs/`
> 和 `runtime/*/mihomo.json` **包含节点凭据**。`metadata/` 已设为仅属主可访问
> （700）；对外分发前请先脱敏。

---

## 2. 每个 PCAP 的字段

### 2.1 字段来源与派生规则

数据本身没有显式的 `task_id`/`pair_id`/`session_id`/`capture_id`。下表给出可用的
来源与派生方式；`metadata/capture_index.csv` 已把结果固化为每 PCAP 一行。

| 你需要的字段 | 来源 / 派生 | 说明 |
|---|---|---|
| `capture_id` | `pcap/` + `MANIFEST.csv:file` | 每个 PCAP 唯一，例如 `pcap/Pure_Proxy/vless/000webhost.com/001.pcap` |
| `task_id` | `_meta.<job>`（如 `pure__vless`） | 任务/运行级 ID，不是单次请求 ID |
| `pair_id` | Pairs：`task_id` + `domain` + `index`（竖线连接）；其余为空 | 同一对 `_pre`/`_post` 共享 |
| `session_id` | **不存在** | 见下方说明；提供 `session_id_derived` 作为连接键 |
| `condition` | `mode` + `node` 派生 | 9 类，见 §2.2 |
| `wrapper` | 外层代理协议：`vless`/`anytls`/`hysteria2`/`trojan`/`ss`/`vmess`；NonTor 为 `none` | PCAP 里抓到的协议 |
| `tor_layer` | `none` / `obfs4` / `webtunnel` | Tor 层封装，见 §2.2 |
| `transport` | validator summary：`udp_packets>0` → `udp`，否则 `tcp`；Pairs 的 `_pre` 固定 `tcp` | Hysteria2 为 UDP |
| `domain` | `MANIFEST.csv` / `_meta.jsonl` | 目标域名 |
| `index` / `file_role` | 文件名 `<NNN>_pre.pcap` / `<NNN>_post.pcap`（或单文件 `<NNN>.pcap`） | `single` / `pre` / `post` |
| `node` | `_meta.node` | 实际使用的节点 ID |
| 采集时间 | `_meta.ts`（UTC）、`capture_index.ts_cst`（UTC+8） | 单元级时间 |
| HTTP 结果 | `_meta.http`：`ok/status/duration/body_len/final_url` | 单元级 |
| PCAP 大小 | `MANIFEST.bytes` | 单文件字节数 |
| 端点 | `_meta.validator_pre/post.summary.remote_endpoints` / `local_endpoints` | 字典：`ip:port → 包数` |
| 匹配计数 | `matched_packets`、`matched_payload_c2s/s2c` | 匹配代理端点的包/载荷 |

**`session_id` 的缺口**：采集器没有记录传输层 session/connection ID。每个
`_meta` 记录对应一次 HTTP 事务/一个 capture unit；Pairs 的 pre/post 共享同一记录。
`capture_index.csv` 中的 `session_id_derived = <task_id>|<domain>|<index>` 只是
一个稳定的连接键，**不能当作真实的 TCP/UDP session ID**。如果你需要真实
session，需要在 PCAP 层用 5-tuple + 时间排序重建（见 §4）。

### 2.2 `condition` / `tor_layer` 派生表

| mode | node 前缀 | condition | wrapper | tor_layer |
|---|---|---|---|---|
| pure | 非 `self-`/`direct-` | `pure_public_node` | 协议 | `none` |
| pure | `self-` | `pure_selfhost_local` | 协议 | `none` |
| pure | `direct-` | `pure_selfhost_direct` | 协议 | `none` |
| top | `self-` | `top_selfhost` | 协议 | `obfs4` |
| top | 其他 | `top_public_node` | 协议 | `obfs4` |
| pairs | `direct-` | `pairs_webtunnel` | 协议 | `webtunnel` |
| pairs | `self-` | `pairs_selfhost_local` | 协议 | `obfs4` |
| pairs | 其他 | `pairs_public_obfs4` | 协议 | `obfs4` |
| nontor | 空 | `nontor_direct` | `none` | `none` |

### 2.3 生成 / 使用 `capture_index.csv`

已生成：`metadata/capture_index.csv`，78,899 行，**0 个 MANIFEST 行缺少元数据**。

重新生成（在 `metadata/` 下）：

```bash
python3 code/build_capture_index.py --root . --out ../capture_index.csv
```

主要列：

```text
capture_id, task_id, pair_id, session_id_derived, condition, wrapper,
tor_layer, transport, domain, index, file_role, node, ts_utc, ts_cst,
http_ok, http_status, scheme, duration_s, body_len, pcap_bytes,
validator_valid, matched_packets, remote_endpoints, local_endpoints
```

注意：

- `_meta` 共 57,908 条记录，但最终 PCAP 是 78,899 个；Pairs 的一对 pre/post
  共享 1 条记录，另有少量 `example.com` / `www.baidu.com` 测试记录不在 MANIFEST。
- 以 `MANIFEST.csv` 为准；`capture_index.csv` 是派生文件，已按 MANIFEST 逐行连接。
- `http_status` 只保留 200–399 的有效单元；失败尝试在 `_meta/*_failures.jsonl`。

---

## 3. 节点、服务器、客户端、配置哈希与时间窗

### 3.1 最终单元实际使用的节点

| 协议 / 模式 | 最终节点（单元数） | 实际 server:port | 说明 |
|---|---|---|---|
| Pure VLESS | `vl0196` × 5,000 | `bgp03.accuhearts.com:8080`（解析到 119.147.123.50） | 公网 VLESS |
| Pure AnyTLS | `an0004` × 5,000 | `usdklax.16816801.xyz:11348`（166.0.26.57） | 公网 AnyTLS |
| Pure Hysteria2 | `hy0030` × 5,000 | `hksdk07.18838008.xyz:25300–26300`（58.152.113.91） | 公网 Hy2/UDP |
| Pure Trojan | `tr0170` 213 / `tr0199` 43 / `tr0126` 40 / `tr0177` 22 / `tr0202` 12 / `self-trojan` 760 / `direct-trojan` 4,199 | 公网 tr*:443；自建 172.31.0.10/0.21:8443 | 公私混合 |
| Pure SS | `self-ss` 756 / `direct-ss` 4,460 | 172.31.0.10:8388 / 172.31.0.21:8388 | 自建 Xray |
| Pure VMess | `self-vmess` 626 / `direct-vmess` 4,374 | 172.31.0.10:8445 / 172.31.0.21:8445 | 自建 Xray |
| ToP VLESS | `self-vless` × 211 | 172.31.0.10:8444 | Tor + obfs4 |
| ToP AnyTLS | `an0004` × 439 | usdklax.16816801.xyz:11348 | Tor + obfs4 |
| ToP Hysteria2 | `hy0030` × 214 | hksdk07.18838008.xyz:25300–26300 | Tor + obfs4 |
| ToP Trojan | `self-trojan` × 156 | 172.31.0.10:8443 | Tor + obfs4 |
| ToP SS | `self-ss` × 183 | 172.31.0.10:8388 | Tor + obfs4 |
| ToP VMess | `self-vmess` × 137 | 172.31.0.10:8445 | Tor + obfs4 |
| Pairs VLESS | `direct-vless` 4,871 / `self-vless` 209 | 172.31.0.21:8444 / 172.31.0.10:8444 | WebTunnel / 早期 |
| Pairs AnyTLS | `an0004` × 549 | usdklax.16816801.xyz:11348 | 公网 + obfs4 |
| Pairs Hysteria2 | `hy0030` × 258 | hksdk07.18838008.xyz:25300–26300 | 公网 + obfs4 |
| Pairs Trojan | `direct-trojan` 4,908 / `self-trojan` 132 | 172.31.0.21:8443 / 172.31.0.10:8443 | WebTunnel / 早期 |
| Pairs SS | `direct-ss` 4,897 / `self-ss` 163 | 172.31.0.21:8388 / 172.31.0.10:8388 | WebTunnel / 早期 |
| Pairs VMess | `direct-vmess` 4,906 / `self-vmess` 134 | 172.31.0.21:8445 / 172.31.0.10:8445 | WebTunnel / 早期 |
| NonTor | 无节点 | 目标 IP（每 PCAP 不同） | 真直连 |

完整 72 行映射见 `metadata/NODE_MAP.csv`，包含：

- `runtime_dir`、`capture_job`、`runtime_phase`
- `node_id`、`server`、`port`、`selfhost`、`allowed_udp`、`allowed_endpoints`
- `mihomo_sha256`

重要观察：虽然 `runtime/` 中某些任务配置了多节点候选池（Pure VLESS 17 个、
AnyTLS 7 个、Hy2 17 个、Trojan 8 个），但**最终单元实际集中在一个或少数节点**；
RQ 分析时不能把候选池数量当作实际节点多样性。

### 3.2 客户端 / 服务器版本

| 组件 | 版本 | 角色 |
|---|---|---|
| Python | 3.11 | 采集容器内 crawler |
| mihomo | v1.19.29 | 客户端 SOCKS/前置 |
| Tor | 0.4.9.11 | Tor 客户端（日志已核实） |
| lyrebird | 15.0.26（Tor expert bundle） | WebTunnel PT |
| Xray-core | 26.3.27 | 自建 Trojan/SS/VLESS/VMess 前置与服务端 |
| tcpdump | Debian 容器内 | 抓包 |
| Docker | 28.3.0 | 运行环境 |
| 服务器系统 | Debian 6.12.35（`debian`） | 本次分析服务器 |
| tshark | 4.0.17 | 服务器已安装，用于流级提取 |
| Python（服务器） | 3.13.5 | 分析环境 |

### 3.3 配置哈希

完整列表：`metadata/CONFIG_SHA256SUMS.txt`（209 项，含 `_preflight/`、
`runtime/`、`config/`、`code/`、MANIFEST/COUNTS/FINAL_REPORT）。
关键项：

| 文件 | SHA256 |
|---|---|
| `runtime/pure-vless/mihomo.json` | `dc1f49b981801cab68bf2dd5afe66e87e945ab6a08280926483462f9509e80ae` |
| `runtime/top-vless-local/mihomo.json` | `c9cff2733f68894109c3c6d01460c77e857f5db0e4d1d64223faebaac06df0a1` |
| `runtime/pairs-vless-wt/mihomo.json` | `2dea25e67be8286caa1c36e1a56488c0a40dbf401040554e35be6e4d89a917aa` |
| `runtime/pairs-anytls/mihomo.json` | `e25b348d567f1c95de55afb56121668cf75d5f4dee0432e3fc7c3ff563a8fa47` |
| `runtime/pure-trojan-direct/mihomo.json` | `06d1332965558f4c4691aa17dc7992509f42ea11563009dcee3fd2ef80074f34` |
| `config/server/config.json` | `03ab7d6dfc4be05920626bc74c52067c2f94ef0c8383d5b72ca4224ba7c720eb` |
| `config/server/config-direct.json` | `c65a6cbe177bd5860acee843aa013b92fe91b106c64a473bf5ff33959add93de` |
| `config/server/upstream-hy2.json` | `3d3e0b790cb6a50c7c172b3bd2a03f7d73b973db975b97ad3569a3848d3ded41` |
| `code/capture.py` | `526cba626bd9e3c903ed2ffcc8a04b5b738274558b24398ea338a1341ce8a0e5` |
| `code/pcap_validate.py` | `63fedc44bd4041d91139a68f80467fabef84ecffd3f0c0e492393ef3ba2db817` |
| `MANIFEST.csv` | `e554afe5a3799eb3b4d71aed74f4421a2ff1706a094c06b9cafdd94471ca9721` |
| `COUNTS.json` | `6bd3bc30e67cca5fa7f3ece9c94144de82adf957b382ab44d1a9c226757689b8` |
| `FINAL_REPORT.md` | `c708a282310121748768d4bb6df40504ab4a8a9ece7c232e2e2659e95eb2b357` |
| `capture_index.csv` | `204e52dd6894b1407110f42101ccc0871894ebb1cb5ffa12d3a9db45c09c2c2b` |
| `NODE_MAP.csv` | `5f417f5a6ec898eee04e9cbf8c33fdd4c2dd1ca9da0086e6b851c1519339f402` |

校验：

```bash
cd /mnt/data/zcx/dataset_2610/metadata
sha256sum -c CONFIG_SHA256SUMS.txt
```

### 3.4 逐任务采集窗口（`_meta.ts`，UTC+8）

**Pure**

| 协议 | 单元 | 采集窗口（CST） | runtime 目录 |
|---|---:|---|---|
| VLESS | 5,000 | 2026-10-28 18:17:34 → 10-29 00:17:51 | `pure-vless` |
| AnyTLS | 5,000 | 2026-10-28 18:17:40 → 10-29 06:22:45 | `pure-anytls` |
| Hysteria2 | 5,000 | 2026-10-28 18:17:38 → 10-29 00:39:48 | `pure-hysteria2` |
| Trojan | 5,289 | 2026-10-28 18:18:07 → 10-30 08:32:17 | `pure-trojan` / `-local` / `-direct` |
| SS | 5,216 | 2026-10-29 10:38:47 → 10-30 08:48:58 | `pure-ss-local` / `-direct` |
| VMess | 5,000 | 2026-10-29 10:49:08 → 10-31 20:06:19 | `pure-vmess-local` / `-direct` |

**Tor_over_Proxy**

| 协议 | 单元 | 采集窗口（CST） | runtime 目录 |
|---|---:|---|---|
| VLESS | 211 | 2026-10-29 10:43:35 → 11:36:28 | `top-vless-local` |
| AnyTLS | 439 | 2026-10-29 10:23:39 → 15:07:28 | `top-anytls` |
| Hysteria2 | 214 | 2026-10-29 10:22:31 → 11:36:26 | `top-hysteria2` |
| Trojan | 156 | 2026-10-29 10:43:30 → 11:36:31 | `top-trojan-local` |
| SS | 183 | 2026-10-29 10:51:36 → 11:36:29 | `top-ss-local` |
| VMess | 137 | 2026-10-29 10:50:33 → 11:36:31 | `top-vmess-local` |

**Traffic_Pairs**

| 协议 | 单元 | 采集窗口（CST） | runtime 目录 |
|---|---:|---|---|
| VLESS | 5,080 | 2026-10-29 10:43:49 → 10-31 17:20:23 | `pairs-vless-local` / `-wt` |
| AnyTLS | 549 | 2026-10-29 10:22:42 → 16:51:16 | `pairs-anytls` |
| Hysteria2 | 258 | 2026-10-29 10:22:04 → 11:36:27 | `pairs-hysteria2` |
| Trojan | 5,040 | 2026-10-29 10:44:13 → 10-31 17:35:22 | `pairs-trojan-local` / `-wt` |
| SS | 5,060 | 2026-10-29 10:49:50 → 10-31 17:56:02 | `pairs-ss-local` / `-wt` |
| VMess | 5,040 | 2026-10-29 10:49:57 → 10-31 17:07:33 | `pairs-vmess-local` / `-wt` |

**NonTor**

| 类别 | 单元 | 采集窗口（CST） |
|---|---:|---|
| NonTor | 5,000 | 2026-10-28 18:18:43 → 10-29 13:41:34 |

### 3.5 按 condition 的时间窗（用于 D1–D4 分层）

| condition | 单元 | 采集窗口（CST） |
|---|---:|---|
| `pure_public_node` | 15,330 | 2026-10-28 18:17:34 → 10-29 06:22:45 |
| `pure_selfhost_local` | 2,142 | 2026-10-29 10:38:45 → 11:36:21 |
| `pure_selfhost_direct` | 13,033 | 2026-10-29 15:36:51 → 10-31 20:06:19 |
| `top_selfhost` | 687 | 2026-10-29 10:43:30 → 11:36:31 |
| `top_public_node` | 653 | 2026-10-29 10:22:31 → 15:07:28 |
| `pairs_webtunnel` | 19,582 | 2026-10-30 11:55:50 → 10-31 17:56:02 |
| `pairs_selfhost_local` | 638 | 2026-10-29 10:43:49 → 11:36:28 |
| `pairs_public_obfs4` | 807 | 2026-10-29 10:22:04 → 16:51:16 |
| `nontor_direct` | 5,000 | 2026-10-28 18:18:43 → 10-29 13:41:34 |

---

## 4. PCAP 内 5-tuple / 端点映射

### 4.1 现有字段能给出什么

每条 `_meta` 记录的 validator summary 已经包含：

```json
{
  "tcp_packets": 1122,
  "udp_packets": 0,
  "matched_packets": 505,
  "matched_payload_c2s": 18296,
  "matched_payload_s2c": 267221,
  "remote_endpoints": {"119.147.123.50:8080": 505},
  "local_endpoints": {}
}
```

- `remote_endpoints` / `local_endpoints`：**端点级**字典，键为 `ip:port`，值为包数。
- `matched_packets` / `matched_payload_*`：匹配所选代理端点/端口后的包数与载荷。
- 这些字段能告诉你“有哪些外层端点”，但**不保存每个 5-tuple 的
  src_port、逐流字节数、首末时间，也不做 target/auxiliary 分类**。

### 4.2 5-tuple 分类规则（建议）

对每个 PCAP 解析流（tshark conversation 或等价解析器），按以下优先级分类：

1. **allowed 端点**：从 `runtime/<job>/meta.json` 的 `nodes[].server:port`、
   `allowed_endpoints` 和 `allowed_ports` 构造。
2. **`target_outer`**：目的端点属于 allowed 端点、且该流是到该端点包数/字节数
   最大的一条；这是主目标外层连接。
3. **`parallel_wrapper`**：同样到 allowed 端点、但不是最大的一条；通常是
   并行连接、预连接、HTTP/2/QUIC 辅助流或连接池。
4. **`auxiliary_external`**：到其他公网端点的流；可能是重定向/CDN/分析/OCSP。
   在 NonTor 中，所有公网流都属于目标流量，最大的一条为 `target_main`，其余为
   `target_auxiliary`。
5. **`local_control`**：`127.0.0.1` 回环流。Pairs 的 `_pre` 是
   `127.0.0.1:<临时端口> ↔ 127.0.0.1:7890` 的 SOCKS 通道；mihomo 控制器
   （9090）或 Tor SOCKS/Control（9050/9051）也归入此类。
6. **`dns`**：53 端口；采集 BPF 已排除 `port 53`，正常 PCAP 中不应出现。

Pairs 的特殊规则：

- `_pre`：Tor → mihomo SOCKS，5-tuple 两端都在 loopback；多个临时端口 =
  多个并行的 SOCKS 连接。
- `_post`：mihomo 前置 → Xray/公网节点；`direct-*` 为 172.31.0.21:8444/8443/
  8388/8445（WebTunnel 路径），public 节点为 an0004/hy0030。
- 同一 `index` 的 pre/post 用 `pair_id` 关联。

### 4.3 样本证据（tshark `-q -z conv,tcp -z conv,udp`）

| PCAP | 5-tuple / conversation | 包数 | 分类 |
|---|---|---:|---|
| Pure/VLESS `000webhost.com/001.pcap` | 172.17.0.2:53200 ↔ 119.147.123.50:8080 | 1,122 | `target_outer`（主） |
| 同上 | 172.17.0.2:53194 ↔ 119.147.123.50:8080 | 40 | `parallel_wrapper` |
| 同上 | 172.17.0.2:53178 ↔ 119.147.123.50:8080 | 36 | `parallel_wrapper` |
| ToP/VLESS `amazon.com/001.pcap` | 172.31.0.4:45818 ↔ 172.31.0.10:8444 | 55 | `target_outer` |
| 同上 | 172.31.0.4:45810 ↔ 172.31.0.10:8444 | 4 | `parallel_wrapper` |
| Pairs/VLESS `0.datadog.pool.ntp.org/001_pre.pcap` | 127.0.0.1:40530 ↔ 127.0.0.1:7890 | 473 | `local_control`（SOCKS pre） |
| Pairs/VLESS `0.datadog.pool.ntp.org/001_post.pcap` | 172.31.0.2:52354 ↔ 172.31.0.21:8444 | 593 | `target_outer`（WebTunnel front） |
| Pairs/Hy2 `amazon.com/001_pre.pcap` | 127.0.0.1:43838 ↔ 127.0.0.1:7890 | 55 | `local_control`（SOCKS pre） |
| Pairs/Hy2 `amazon.com/001_post.pcap` | 172.17.0.5:35726 ↔ 58.152.113.91:25858（UDP） | 104 | `target_outer`（公网 Hy2） |
| NonTor `163.com/001.pcap` | 172.17.0.6:45388 ↔ 61.157.38.35:80 | 381 | `target_main` |
| 同上 | 172.17.0.6:55648 ↔ 59.111.160.244:443 | 21 | `target_auxiliary` |

这说明同一个 PCAP 内**确实可能有多条 5-tuple**；端点摘要会把它们合并到
`remote_endpoints` 的同一 key 下（例如 Pure 样本的 3 条流都指向
`119.147.123.50:8080`），所以要做连接级 manifest 必须回到 PCAP 解析。

### 4.4 流级提取命令

服务器已安装 tshark 4.0.17：

```bash
tshark -r pcap/Pure_Proxy/vless/000webhost.com/001.pcap \
       -q -z conv,tcp -z conv,udp
```

对全部 78,899 个 PCAP 逐个运行会有启动开销；建议并行（例如 8–16 个 worker），
输出每个 conversation 的 `src,dst,proto,packets,bytes,first_ts,last_ts,duration`，
再用 §4.2 规则标注 `target_outer` / `parallel_wrapper` / `auxiliary_external` /
`local_control`。

建议的连接级 manifest 字段：

```text
capture_id, flow_id, pair_id, ts_first, ts_last, duration,
src_ip, src_port, dst_ip, dst_port, proto, packets, bytes_c2s, bytes_s2c,
endpoint_class, is_allowed_endpoint, node_id, condition, file_role
```

---

## 5. Pure 与 ToP 是否同一任务/网站/配置/节点/条件

**结论：不是同一任务，不是同一配置，条件也不同。** 它们只共享站点源，
并部分共享节点 ID 或节点池。

| 维度 | Pure | ToP | 是否相同 |
|---|---|---|---|
| 任务 | `pure__*`，独立容器/运行 | `top__*`，独立容器/运行 | ❌ |
| 站点源 | `docker/configs/top1000.txt` | `docker/configs/top1000.txt` | ✅ 同源 |
| 实际域名 | 每协议 448–627 个 | 每协议 14–44 个（ToP 提前停止） | ❌ 子集很小 |
| 节点 | VLESS public `vl0196`；AnyTLS `an0004`；Hy2 `hy0030`；Trojan 公私混合；SS/VMess 自建 | VLESS/Trojan/SS/VMess `self-*`；AnyTLS `an0004`；Hy2 `hy0030` | ⚠️ 部分重叠 |
| 配置 | `runtime/pure-*` | `runtime/top-*` | ❌ 不同文件/哈希 |
| 网络条件 | 无 Tor | Tor + obfs4 → mihomo → 外层代理 | ❌ |
| 时间窗 | 10-28 18:17 → 10-31 20:06（分协议） | 10-29 10:22–15:07 | ⚠️ 有墙钟重叠，但任务/条件不同，非配对 |

域名重叠（`MANIFEST.csv`，按协议）：

| 协议 | Pure 域名 | ToP 域名 | 交集 | Jaccard |
|---|---:|---:|---:|---:|
| VLESS | 627 | 22 | 22 | 0.035 |
| AnyTLS | 558 | 44 | 42 | 0.075 |
| Hysteria2 | 626 | 24 | 24 | 0.038 |
| Trojan | 551 | 16 | 16 | 0.029 |
| SS | 542 | 19 | 19 | 0.035 |
| VMess | 448 | 14 | 13 | 0.029 |

配置差异示例：`runtime/pure-vless/mihomo.json` =
`dc1f49b9…`，`runtime/top-vless-local/mihomo.json` = `c9cff273…`，两者不同。
AnyTLS/Hy2 虽然使用同一节点 ID（an0004/hy0030），但任务、runtime 目录、
时间窗和 Tor 层条件不同，不能当作“同一条件下的配对样本”。

因此 RQ1 中若要比较 Pure 与 ToP，应按 domain+protocol 匹配后作为**不同条件**
处理；不能假设同一任务、同一配置或同一节点。

---

## 6. 是否存在真实 `arrival_timestamp`

**没有。** 当前数据只能做 **capture-order replay**，不能还原真实到达时间。

证据：

- PCAP 是 classic pcap，全局 header magic = `0xa1b2c3d4`（**微秒**精度），
  不是纳秒/硬件时间戳格式。
- 采集命令为 `tcpdump -i <iface> -w <file> -s 0 -U -n <bpf>`，没有
  `--time-stamp-precision=nano`、没有硬件时间戳、没有 receiver 侧时间同步。
- 样本 `Pure_Proxy/vless/google.com/001.pcap` 首包时间：
  `2026-10-28 18:17:29.761070 CST`；对应 `_meta.ts`：
  `2026-10-28 18:17:34 CST`（在抓包开始之后），`http.duration = 2.984 s`。
- `_meta.ts` 是单元记录时间（抓取完成/记录时），`http.duration` 是客户端
  请求耗时；两者都不是网络到达时间。

因此：

- PCAP 内的 `frame.time_epoch` 是**本地抓包时刻**（eth0/lo 上内核打的时间戳），
  不是代理服务器/目标服务器的 arrival timestamp。
- 可以在单个 PCAP 内按包时间排序做 capture-order replay；
  不能把它当作端到端到达时间、不能做精确的网络延迟/RTT 分解。

---

## 7. D1–D4 划分与分组规则

数据里没有预定义的 D1–D4。下面给出两套可执行划分；任选其一或作为分层维度。

### 7.1 方案 A：按采集模式（推荐，语义最清晰）

| 组 | 定义 | 单元数 | 子条件 |
|---|---|---:|---|
| **D1 = Pure** | 无 Tor，mihomo → 公网/自建前置 | **30,505** | public 15,330；self-local 2,142；self-direct 13,033 |
| **D2 = ToP** | Tor + obfs4 → mihomo → 外层代理 | **1,340** | selfhost 687；public 653 |
| **D3 = Pairs** | 双视角（pre/post） | **21,027** | WebTunnel 19,582；self-local 638；public+obfs4 807 |
| **D4 = NonTor** | 真直连 | **5,000** | direct 5,000 |
| **合计** | | **57,872** | |

### 7.2 方案 B：按 wrapper 层（适合按封装分类做 RQ）

| 组 | 定义 | 单元数 |
|---|---|---:|
| **D1 = 公网节点 wrapper** | Pure public + ToP public + Pairs public+obfs4 | **16,790** |
| **D2 = 自建 Xray wrapper** | Pure selfhost（local+direct）+ ToP selfhost + Pairs selfhost local | **16,500** |
| **D3 = WebTunnel wrapper** | Pairs VLESS/Trojan/SS/VMess（`direct-*`） | **19,582** |
| **D4 = 直连** | NonTor | **5,000** |
| **合计** | | **57,872** |

注意：方案 B 的 D1 内部仍混合 Pure（无 Tor）与 ToP（有 Tor），D2 内部也混合
Pure/ToP/Pairs；如果把 Tor 层作为变量，应使用方案 A。

### 7.3 分组公式

```text
condition = mode + "_" + node_class
  node_class = public_node | selfhost_local | selfhost_direct | webtunnel
wrapper    = vless | anytls | hysteria2 | trojan | ss | vmess | none
tor_layer  = none | obfs4 | webtunnel
window     = min(_meta.ts), max(_meta.ts) per condition
config     = runtime/<job>/mihomo.json 的 SHA256
server     = runtime/<job>/meta.json 的 nodes[].server:port
client     = mihomo/ Tor / Xray 版本 + code/capture.py 哈希
```

这些字段已经在 `capture_index.csv` 和 `NODE_MAP.csv` 中可直接筛选用。

---

## 8. 缺口与使用注意

1. **没有真实 `session_id`**：只有 job + domain + index 派生键；无法区分同一
   域名多次 HTTP 事务之外的传输层 session。
2. **没有持久化逐 5-tuple 流表**：`_meta` 只有端点→包数摘要；连接级 manifest
   必须从 PCAP 重新提取（§4）。
3. **没有 arrival timestamp**：只能 capture-order replay（§6）。
4. **`_meta` 记录数 > 最终单元数**：57,908 条记录 vs 57,872 单元/78,899 文件；
   多出的记录是 `example.com`/`www.baidu.com` 测试或重复尝试，不在 MANIFEST。
5. **MANIFEST 的 `file` 是相对数据集根的路径**；服务器上需加 `pcap/` 前缀。
   路径中不能假设每个域名都有 max/site 个样本（失败/限流会少）。
6. **ToP 与 Pairs AnyTLS/Hy2 是部分数据**：分别 1,340 单元、549/258 对；
   不能当作完整条件组。
7. **`_preflight` 与 `runtime` 含凭据**：`metadata/` 已设为 700；不要公开分发，
   或先脱敏再给协作者。
8. **`config/server/` 不含证书私钥**：只同步了 JSON 配置；证书在本地原目录
   `docker/recapture/server/certs/`，需要时另行处理。

---

## 9. 快速命令

```bash
# 1) 元数据根
cd /mnt/data/zcx/dataset_2610/metadata

# 2) 校验所有列出的配置/脚本哈希
sha256sum -c CONFIG_SHA256SUMS.txt

# 3) 重新生成每 PCAP 索引（若修改了 MANIFEST/_meta）
python3 code/build_capture_index.py --root . --out ../capture_index.csv

# 4) 查看实际节点映射
column -s, -t NODE_MAP.csv | head

# 5) 提取单个 PCAP 的 5-tuple conversation
tshark -r ../pcap/Pure_Proxy/vless/000webhost.com/001.pcap -q -z conv,tcp -z conv,udp

# 6) 统计某个条件
python3 - <<'PY'
import csv
rows = list(csv.DictReader(open('../capture_index.csv', encoding='utf-8')))
from collections import Counter
print(Counter(r['condition'] for r in rows))
PY
```

---

## 10. 交付清单

```text
metadata/MANIFEST.csv
metadata/COUNTS.json
metadata/FINAL_REPORT.md
metadata/capture_index.csv
metadata/NODE_MAP.csv
metadata/CONFIG_SHA256SUMS.txt
metadata/_meta/                 # 19 个 job JSONL + failures + progress + logs
metadata/_preflight/            # 节点/网桥/可达性/测试配置/订阅快照
metadata/runtime/               # 27 个 mihomo.json + meta.json
metadata/config/                # server JSON + 网桥 + torrc + 站点列表
metadata/code/                  # capture/validate/build_capture_index 等
../CAPTURE_METADATA.md          # 本文档
../PCAP_PROTOCOL_MAP.md
../DATA_COMPOSITION.md
```

最小阻塞项 1–4 的入口：

- **路径入口**：`/mnt/data/zcx/dataset_2610/metadata/`
- **每 PCAP 字段**：`metadata/capture_index.csv`
- **节点/配置/窗口**：`metadata/NODE_MAP.csv`、`metadata/CONFIG_SHA256SUMS.txt`、§3
- **流级映射**：`_meta` 端点摘要 + `tshark` + §4 规则
