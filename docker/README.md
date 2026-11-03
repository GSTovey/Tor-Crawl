# TorCrawl Docker — 设置指南

## 1. 填写代理节点配置

编辑 `configs/` 目录下的 Xray 配置文件，将 `YOUR_*` 占位符替换为你的实际节点信息：

| 文件 | 协议 | 需要填写 |
|------|------|----------|
| `xray-ss.json` | Shadowsocks | 服务器地址、端口、加密方式、密码 |
| `xray-trojan.json` | Trojan | 服务器地址、端口、密码、SNI |
| `xray-vmess.json` | VMess | 服务器地址、端口、UUID、WS 路径、SNI |
| `xray-vless.json` | VLESS | 服务器地址、端口、UUID、WS 路径、SNI |

### 从 Clash Verge 导出节点配置

如果你已有 Clash Verge 配置，可以从 Clash 配置文件中提取节点信息：

1. 打开 Clash Verge → Profiles → 右键你的订阅 → "Edit" 或查看本地配置文件
2. 配置文件通常在: `%APPDATA%/io.github.clash-verge-rev.clash-verge-rev/profiles/`
3. 找到对应协议的节点，提取: `server`, `port`, `uuid`/`password`, `network`, `path`, `sni` 等字段
4. 填入对应的 `xray-*.json` 模板

> 如果只有部分协议的节点，在 `docker-compose.yml` 中注释掉没有的服务即可。

## 2. 设置爬取目标

编辑 `docker-compose.yml` 中的环境变量，或创建 `.env` 文件：

```bash
cp .env.example .env
# 编辑 .env 设置目标和深度
```

## 3. 构建并启动

```bash
# 构建镜像
docker compose build

# 启动所有协议容器（后台运行）
docker compose up -d

# 或只启动 VLESS（如果你只有 VLESS 节点）
docker compose up torcrawl-vless -d

# 查看日志
docker compose logs -f torcrawl-vless

# 停止全部
docker compose down
```

## 4. 查看结果

爬取结果保存在 `output/` 目录下，按协议分类：

```
output/
├── ss/          # Shadowsocks 抓取结果
├── trojan/      # Trojan 抓取结果
├── vmess/       # VMess 抓取结果
└── vless/       # VLESS 抓取结果
```

## 容器内链路

```
                    Docker Container
   ┌────────────────────────────────────────────┐
   │                                             │
   │  torcrawl.py ──→ Tor SOCKS5 (:9050)        │
   │                         │                   │
   │                    torrc: Socks5Proxy       │
   │                         │                   │
   │                         ↓                   │
   │                  Xray inbound (:1080)       │
   │                         │                   │
   │                  Xray outbound              │
   │                  (SS/Trojan/VMess/VLESS)    │
   │                         │                   │
   └─────────────────────────┼───────────────────┘
                             │
                             ↓
                    远程代理服务器
                             │
                             ↓
                      Tor Entry Node
                             │
                             ↓
                      Tor 网络
                             │
                             ↓
                        目标站点
```
