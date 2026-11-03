# Traffic Capture Dataset — Documentation

本目录归档 2026-10-28 重采的文档。**原始 PCAP 数据不随仓库发布**，仅保留
采集代码、配置模板和文档。数据根目录（本地）为 `2026-10-28_Recapture/`。

## 数据布局

```
<data-root>/
  Pure_Proxy/<protocol>/<domain>/<NNN>.pcap
  Tor_over_Proxy/<protocol>/<domain>/<NNN>.pcap
  Traffic_Pairs/<protocol>/<domain>/<NNN>_pre.pcap + <NNN>_post.pcap
  Tor_Direct/NonTor/<domain>/<NNN>.pcap
  _pilot/                  manually verified validation samples
  _preflight/              node tests, runtime configs, reachable lists
  _meta/                   logs, progress, per-capture JSONL metadata
  _excluded_mieru/         excluded Mieru data (not in dataset)
  MANIFEST.csv             one row per valid PCAP
  COUNTS.json              machine-readable counts
```

## 四种采集模式

| 目录 | 链路 | 抓取位置 |
|---|---|---|
| `Pure_Proxy` | crawler -> proxy protocol -> remote -> target | 容器 `eth0`（协议封装后） |
| `Tor_over_Proxy` | crawler -> Tor -> front proxy -> remote -> Tor network -> target | 容器 `eth0`（Tor 流量被外层协议封装） |
| `Traffic_Pairs` | 同上，同一请求双视角 | `_pre` = `lo`（Tor -> 前置 SOCKS），`_post` = `eth0`（封装后） |
| `Tor_Direct/NonTor` | crawler -> target（无 Tor、无代理封装） | 容器 `eth0` |

## 校验规则

一个 PCAP 只有满足以下条件才会保留：

1. HTTP(S) 状态码为 200–399。
2. 与所选代理端点之间存在双向传输 payload（TCP；Hysteria2 为 UDP/QUIC）。
3. 端点匹配所选节点/端口或允许的自建端点。
4. 不包含宿主机 Clash `192.168.65.254:7897` 的流量。
5. 数据开始前没有 RST。

无效尝试会被删除，并记录在 `_meta/<job>_failures.jsonl`。

## 复现

采集脚本与容器定义在 [docker/recapture/](../../docker/recapture/)，
总体流程见该目录的 README。统计与报告：

- [TRAFFIC_REPORT.md](TRAFFIC_REPORT.md) — 四种模式规模总览
- [FINAL_REPORT.md](FINAL_REPORT.md) — 本次重采最终统计
- [PCAP_PROTOCOL_MAP.md](PCAP_PROTOCOL_MAP.md) — PCAP 分类速查
- [DATA_COMPOSITION.md](DATA_COMPOSITION.md) — 数据构成细节
- [CAPTURE_METADATA.md](CAPTURE_METADATA.md) — 环境、运行时与元数据
- [NODE_TEST_REPORT.md](NODE_TEST_REPORT.md) — 节点测试
- [MISSING_AND_NEXT_STEPS.md](MISSING_AND_NEXT_STEPS.md) — 后续计划
- [status/](status/) — 各阶段状态快照（历史归档）
