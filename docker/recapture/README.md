# Recapture Pipeline

可复现的 PCAP 采集流水线。设计目标是让同一套脚本分别产出四种数据集：

| 模式 | 说明 | 入口 |
|---|---|---|
| `pure` | 爬虫 -> 代理协议 -> 目标（无 Tor） | `run_all.py` / `run_job.py` |
| `top` | 爬虫 -> Tor -> 前置代理 -> 远程 -> Tor 网络 | `run_*supervisor.py` |
| `pairs` | 同一请求同时抓 `lo` 与 `eth0` 两个视角 | `run_pairs_*supervisor.py` |
| `nontor` | 直连，无代理无 Tor | `run_all.py` / `crawl_pcap_nontor.py` |

## 目录

| 文件 | 作用 |
|---|---|
| `capture.py` | 单次抓取：启动爬虫、tcpdump、校验、落盘 |
| `pcap_validate.py` | PCAP 校验（HTTP 状态、双向 payload、端点匹配、RST） |
| `node_test.py` / `tor_test.py` / `tor_test_all.py` | 节点与 Tor 连通性测试 |
| `precheck_targets.py` | 目标站点预检 |
| `build_inventory.py` | 从订阅/节点列表生成节点清单 |
| `make_runtime.py` / `make_extra_runtime.py` | 生成 mihomo/Xray 运行时配置 |
| `run_job.py` | 运行单个 job |
| `run_all.py` | 批量调度 |
| `run_*_supervisor.py` | 长跑守护：桥接轮换、失败重试、目标计数 |
| `finalize.py` | 汇总 MANIFEST/COUNTS/报告 |
| `build_capture_index.py` | 生成 `capture_index.csv`（路径、大小、索引） |
| `server/` | 自建 Xray 前置（Trojan/SS/VLESS/VMess 入站） |
| `torrc*.template` | Tor / 网桥 / WebTunnel 配置模板 |
| `Dockerfile` | 采集容器镜像 |

## 基本流程

1. **准备节点**：编辑 `docker/configs/xray-*.json`、`docker/configs/clash/*.yaml`
   （仓库中为占位符模板），或通过 `build_inventory.py` 从订阅生成。
2. **预检**：`python node_test.py`、`python tor_test.py` 确认节点与 Tor 可用。
3. **生成运行时配置**：`make_runtime.py` 按 job 生成 `runtime/<job>/`。
4. **采集**：`run_job.py` 或 supervisor 启动容器，抓取并校验。
5. **汇总**：`finalize.py` 输出 MANIFEST/COUNTS，`build_capture_index.py` 建索引。

## 依赖

- Python 3.9+、`pysocks`、`PyYAML`
- Docker / Docker Compose
- 容器内：`tcpdump`、`tor`、`xray`、`mihomo`、`lyrebird`（obfs4/WebTunnel）
- 节点：任一受支持的代理协议（Shadowsocks / Trojan / VMess / VLESS /
  Hysteria2 / AnyTLS / Mieru）

> `mihomo`、`lyrebird` 等二进制不随仓库提交，请从各自官方 release 下载后放入
> `bin/`、`pt/`。网桥配置文件 `bridges_*.txt` 也不入库，按
> `torrc_bridges.template` 的格式自行提供。

## 环境变量（常用）

| 变量 | 用途 |
|---|---|
| `TARGET_TOTAL` | 单 job 目标有效样本数，达到后自动停止 |
| `SITE_LIST` | 站点列表路径（默认 `docker/configs/top1000.txt`） |
| `MIHOMO_API` | mihomo 控制接口，默认 `http://127.0.0.1:9091` |
| `CAPTURE_MODE` | `pure` / `top` / `pairs` / `nontor` |
| `PROTOCOL` | 代理协议名，用于选择配置与输出目录 |

更多参数见各脚本的 `--help` 与
[docs/capture](../../docs/capture/README.md)。
