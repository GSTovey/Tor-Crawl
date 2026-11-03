# Tor-over-Proxy

TorCrawl 默认直连 Tor SOCKS5（`127.0.0.1:9050`）。**Tor-over-Proxy** 模式在
Tor 与网络之间插入一个本地前置代理（Clash / V2Ray / Xray / mihomo 等），
形成如下链路：

```
torcrawl -> Tor SOCKS5 -> 前置代理(localhost) -> 代理协议封装
         -> 远程代理服务器 -> Tor 入口节点 -> Tor 网络 -> 目标站点
```

Tor 的全部出站连接（目录下载、入口节点连接）都会经过前置代理。本功能通过
修改 `torrc` 中的 `Socks5Proxy` / `HTTPSProxy` 指令实现，代码位于
[modules/proxychain.py](../modules/proxychain.py)。

## 命令行参数

| 参数 | 说明 |
|---|---|
| `-up, --upstream-proxy host:port` | 前置代理地址，例如 `127.0.0.1:7897`（宿主机 Clash） |
| `-upt, --upstream-proxy-type {socks5,http}` | 前置代理本地接口类型，默认 `socks5` |
| `-upp, --upstream-proxy-protocol {...}` | 远程协议名（`shadowsocks`/`trojan`/`vmess`/`vless`），仅用于提示，实际由前置代理解析 |
| `-tp, --torrc-path PATH` | 指定 torrc 路径，默认自动探测常见位置 |
| `-ntc, --no-torrc-config` | 不自动修改 torrc（已手动配置时使用） |
| `--verify-chain` | 爬取前验证整条链路（前置代理 -> Tor -> 目标） |

## 示例

Clash Verge 在宿主机监听 `7897`（混合端口）：

```bash
python torcrawl.py -v -u https://example.com -up 127.0.0.1:7897 --verify-chain
```

容器内访问宿主机 Clash：

```bash
python torcrawl.py -v -u https://example.com -up host.docker.internal:7897 -upt socks5
```

前置代理是 HTTP 代理：

```bash
python torcrawl.py -v -u https://example.com -up 127.0.0.1:8080 -upt http
```

## 行为说明

1. 启动时读取并备份 torrc（`torrc.bak.<timestamp>`），写入：

   ```text
   Socks5Proxy 127.0.0.1:7897
   ```

   或对 HTTP 代理写入 `HTTPSProxy`（以及 `UseHTTPSProxy 1`）。
2. 如果 torrc 已有上游代理指令，会先移除旧值再写入，避免重复。
3. 通过 Tor 控制端口或重启服务使配置生效（取决于运行方式）。
4. 使用 `--verify-chain` 时依次检查：前置代理 TCP 可达、Tor SOCKS5 可用、
   出口 IP 获取成功；任一步失败会给出明确错误。
5. `-ntc` 模式下只做探测/验证，不修改 torrc，适合手工维护配置的场景。
6. 爬取结束后可调用 `TorrcManager.restore()` 恢复备份。

## 开发/测试

```bash
python -m pytest modules/tests/test_proxychain.py -v
```

`modules/proxychain.py` 的主要接口：

- `FrontProxyConfig(host, port, proxy_type, protocol)` — 前置代理配置与
  `torrc_directive` 生成。
- `TorrcManager(torrc_path=None)` — 定位/读写 torrc、备份恢复、增删上游代理、
  重载 Tor。
- `check_tcp_connection(host, port)` — TCP 可达性检查。
- `verify_proxy_chain(...)` — 端到端链路验证。
