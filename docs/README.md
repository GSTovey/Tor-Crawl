# 文档归档 / Documentation

本目录归档 TorCrawl 二次开发相关的设计与数据说明。原始采集数据（PCAP、
MANIFEST、节点清单等）不在仓库中，仅保留可复现的代码、配置模板与文档。

## 目录

| 文档 | 内容 |
|---|---|
| [tor-over-proxy.md](tor-over-proxy.md) | Tor-over-Proxy 功能：通过 torrc 把 Tor 的出站流量交给前置代理（Clash/V2Ray/Xray） |
| [capture/README.md](capture/README.md) | 流量采集流水线、数据组织方式与复现步骤 |
| [capture/TRAFFIC_REPORT.md](capture/TRAFFIC_REPORT.md) | 四种采集模式与各协议规模总览 |
| [capture/FINAL_REPORT.md](capture/FINAL_REPORT.md) | 2026-10-28 重采的最终统计与校验规则 |
| [capture/PCAP_PROTOCOL_MAP.md](capture/PCAP_PROTOCOL_MAP.md) | 如何从路径/协议判断一个 PCAP 属于哪一类 |
| [capture/DATA_COMPOSITION.md](capture/DATA_COMPOSITION.md) | 数据构成与链路细节 |
| [capture/CAPTURE_METADATA.md](capture/CAPTURE_METADATA.md) | 采集环境、镜像、运行时与元数据字段 |
| [capture/NODE_TEST_REPORT.md](capture/NODE_TEST_REPORT.md) | 节点连通性/可用性测试结果 |
| [capture/MISSING_AND_NEXT_STEPS.md](capture/MISSING_AND_NEXT_STEPS.md) | 未完成部分与后续计划 |
| [capture/status/](capture/status/) | 采集期间各阶段的状态快照（历史归档） |

## 相关代码

- 爬虫核心：[modules/](../modules/)、[torcrawl.py](../torcrawl.py)
- Tor-over-Proxy：[modules/proxychain.py](../modules/proxychain.py)
- Docker 采集流水线：[docker/](../docker/)
- 重采容器/脚本：[docker/recapture/](../docker/recapture/)
