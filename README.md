# Tor-Crawl

基于 [MikeMeliz/TorCrawl.py](https://github.com/MikeMeliz/TorCrawl.py) 二次开发的 **Tor / 代理协议流量采集框架**。
在原项目“经 Tor 匿名爬取网页”的基础上，增加了 Docker 化的多协议代理链（Xray / Clash Meta）、
tcpdump 自动抓包，以及 Tor-over-Proxy、纯代理、Tor 直连、流量对等多种采集模式，用于构建加密流量分析数据集。

> 本仓库只包含代码与配置模板，**不包含**采集到的 PCAP 数据。

## 采集模式

| 模式 | 链路 | Compose 文件 |
|------|------|--------------|
| Tor over Proxy (ToP) | 爬虫 → Tor → Xray/Clash 代理 → 远程服务器 → Tor 网络 → 目标 | `docker-compose.yml` / `docker-compose.clash.yml` / `docker-compose.v2raya.yml` |
| Pure Proxy | 爬虫 → Xray 代理 → 远程服务器 → 目标（无 Tor） | `docker-compose.pure.yml` |
| Tor Direct / NonTor | 爬虫 → Tor → 目标；或直连目标 | `docker-compose.yml`（`entrypoint_puretor.sh` / `entrypoint_nontor.sh`） |
| Traffic Pairs | 同一请求的代理前 / 代理后双视角抓包 | `docker-compose.yml`（`*-pairs` 服务） |

支持协议：Shadowsocks、Trojan、VMess、VLESS、Hysteria2、AnyTLS、Mieru。

## 目录结构

```
Tor-Crawl/
├── torcrawl.py              # 爬虫主入口（源自 TorCrawl.py，有修改）
├── modules/                 # 爬虫核心模块：crawler / extractor / checker / proxychain / export / visualization
│   └── tests/               # 单元测试
├── res/                     # 爬虫资源：UA 列表、正则、YARA 规则、代理列表
├── docker/
│   ├── Dockerfile           # Xray + Tor + 爬虫镜像
│   ├── Dockerfile.clash     # Clash Meta (mihomo) + Tor + 爬虫镜像
│   ├── docker-compose*.yml  # 各采集模式的服务编排
│   ├── .env.example         # 环境变量模板
│   ├── entrypoints/         # 容器启动脚本（启动 Xray/Clash、Tor、tcpdump 与爬虫）
│   ├── capture/             # 批量抓包脚本：crawl_pcap*.py（按站点列表访问并保存 PCAP）
│   ├── tools/               # 节点获取、配置生成、节点测试等辅助脚本
│   └── configs/             # torrc、Xray/Clash 配置模板、top1000 站点列表
├── docs/
│   ├── DOCKER_SETUP.md      # Docker 使用说明
│   ├── TRAFFIC_REPORT.md    # 已采集数据集的统计报告
│   └── UPSTREAM_README.md   # 原项目 README
├── requirements.txt / setup.py / tox.ini
└── LICENSE                  # GPL-3.0（沿用上游）
```

## 快速开始

### 1. 本地运行爬虫（需本机已运行 Tor，SOCKS5 9050）

```bash
pip install -r requirements.txt
python torcrawl.py -u https://check.torproject.org -c -d 1
```

更多参数见 [docs/UPSTREAM_README.md](docs/UPSTREAM_README.md)。

### 2. Docker 批量抓包

```bash
cd docker
cp .env.example .env               # 设置目标、深度、每站 PCAP 数等
# 编辑 configs/xray-*.json 或 configs/clash/*.yaml，把 YOUR_* 占位符替换为你自己的节点

docker compose build
docker compose up torcrawl-vless -d            # ToP，单协议
docker compose -f docker-compose.pure.yml up -d  # 纯代理
docker compose logs -f
```

抓到的 PCAP 输出在仓库根目录 `output/`（已在 `.gitignore` 中忽略）。

常用环境变量：`TARGET_TOTAL`（目标 PCAP 总数）、`MAX_PCAPS`（每站抓包次数）、`SITE_LIST`（站点列表，默认 `configs/top1000.txt`）、`FETCH_NODES` / `MAX_NODES`（启动时自动获取公共节点）。

### 3. 辅助工具（在 `docker/` 目录下运行）

```bash
python tools/fetch_nodes.py -p vless -n 15     # 从公开源获取节点并生成 Xray 配置
CLASH_SUB_URL=<你的订阅> python tools/fetch_sub.py   # 拆分 Clash 订阅
python tools/gen_configs.py                    # 由节点生成多节点负载均衡配置
bash tools/check_tor_plugins.sh                # 检查 obfs4 / webtunnel 插件
```

## 安全说明

- 仓库中的节点地址、密码、UUID、订阅链接与 obfs4 网桥均已替换为占位符，请自行填写，**不要把真实凭据提交到仓库**。
- `docker/.env`、`proxy_nodes.md` 与所有 `*.pcap` 已加入 `.gitignore`。
- 请仅在合法授权的研究场景中使用本工具，遵守当地法律及目标网站的使用条款。

## 致谢与许可

本项目 fork 自 [MikeMeliz/TorCrawl.py](https://github.com/MikeMeliz/TorCrawl.py)（作者 MikeMeliz），
爬虫核心代码（`torcrawl.py`、`modules/`、`res/`）来源于该项目并做了修改，新增了 `docker/` 下的多协议抓包框架。
按照上游协议，本项目同样以 **GNU GPL-3.0** 发布，详见 [LICENSE](LICENSE)。
