#!/usr/bin/env python3
"""
Node Fetcher — pulls free proxy nodes from xyfqzy/free-nodes GitHub repo,
parses them, and generates Xray config files with automatic failover.

Supports: Shadowsocks, Trojan, VMess, VLESS

Xray failover mechanism:
  Each node gets its own outbound tag.  Xray's built-in observatory
  health-checks every node, and the balancer routes traffic to the
  healthiest one.  If a node goes down, traffic automatically shifts.

Usage:
  python fetch_nodes.py                    # Fetch all, generate configs
  python fetch_nodes.py --protocol vless   # Only VLESS
  python fetch_nodes.py --max-nodes 20     # Limit nodes per protocol
  python fetch_nodes.py --dry-run          # Print without writing files
"""

import argparse
import base64
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

# ── Try to route through local Clash proxy ──────────────────────────
try:
    import socks

    # Detect: inside Docker → host.docker.internal; on host → 127.0.0.1
    _in_docker = os.path.exists("/.dockerenv")
    _CLASH_HOST = os.environ.get(
        "CLASH_HOST",
        "host.docker.internal" if _in_docker else "127.0.0.1"
    )
    _CLASH_PORT = int(os.environ.get("CLASH_PORT", "7897"))
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, _CLASH_HOST, _CLASH_PORT)
    socket.socket = socks.socksocket
    socket.getaddrinfo = lambda *args: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (args[0], args[1]))
    ]
    print(f"[proxy] Routing through Clash SOCKS5 {_CLASH_HOST}:{_CLASH_PORT}")
except ImportError:
    print("[proxy] pysocks not available, using direct connection")
except Exception as e:
    print(f"[proxy] Clash setup failed: {e}, using direct connection")

# ── Constants ───────────────────────────────────────────────────────
REPO_BASE = (
    "https://raw.githubusercontent.com/xyfqzy/free-nodes/main/nodes"
)
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "configs")

# ── Node structures ──────────────────────────────────────────────────

class VmessNode:
    __slots__ = ("address", "port", "uuid", "network", "tls", "path", "host", "sni", "name")
    def __init__(self, address, port, uuid, network="tcp", tls="", path="/", host="", sni="", name=""):
        self.address = address; self.port = int(port); self.uuid = uuid
        self.network = network; self.tls = tls; self.path = path
        self.host = host; self.sni = sni or host; self.name = name


class VlessNode:
    __slots__ = ("address", "port", "uuid", "network", "security", "flow", "sni", "fp", "pbk", "sid", "name")
    def __init__(self, address, port, uuid, network="tcp", security="none",
                 flow="", sni="", fp="chrome", pbk="", sid="", name=""):
        self.address = address; self.port = int(port); self.uuid = uuid
        self.network = network; self.security = security; self.flow = flow
        self.sni = sni; self.fp = fp; self.pbk = pbk; self.sid = sid; self.name = name


class TrojanNode:
    __slots__ = ("address", "port", "password", "security", "sni", "name")
    def __init__(self, address, port, password, security="tls", sni="", name=""):
        self.address = address; self.port = int(port); self.password = password
        self.security = security; self.sni = sni or address; self.name = name


class SSNode:
    __slots__ = ("address", "port", "method", "password", "name")
    def __init__(self, address, port, method, password, name=""):
        self.address = address; self.port = int(port)
        self.method = method; self.password = password; self.name = name


# ── HTTP helpers ─────────────────────────────────────────────────────

def _fetch(url: str, timeout: int = 30) -> str:
    """Fetch a URL with retries, returning decoded text."""
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (TorCrawl)"})
    last_err = None
    for attempt in range(3):
        try:
            return urlopen(req, timeout=timeout).read().decode("utf-8")
        except Exception as e:
            last_err = e
            time.sleep(2)
    raise last_err  # type: ignore[misc]


def _quick_tcp_check(host: str, port: int, timeout: float = 3.0) -> bool:
    """Lightweight TCP reachability check (not thorough, but fast)."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except Exception:
        return False


# ── Parsers ──────────────────────────────────────────────────────────

def parse_vmess(text: str) -> list[VmessNode]:
    nodes = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("vmess://"):
            continue
        try:
            b64 = line[len("vmess://"):]
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            obj = json.loads(base64.b64decode(b64))
            nodes.append(VmessNode(
                address=obj.get("add", ""),
                port=obj.get("port", 443),
                uuid=obj.get("id", ""),
                network=obj.get("net", "tcp"),
                tls=obj.get("tls", ""),
                path=obj.get("path", "/"),
                host=obj.get("host", ""),
                sni=obj.get("sni", ""),
                name=re.sub(r'[^\x00-\x7f]', '', obj.get("ps", "")).strip(),
            ))
        except Exception:
            continue
    return nodes


def parse_vless(text: str) -> list[VlessNode]:
    nodes = []
    # vless://UUID@HOST:PORT?params#description
    pat = re.compile(
        r'vless://([^@]+)@([^:]+):(\d+)\?(.+?)(?:#(.+))?$'
    )
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("vless://"):
            continue
        m = pat.match(line)
        if not m:
            continue
        uuid, host, port, params_str, desc = m.groups()
        params = {}
        for p in (params_str or "").split("&"):
            if "=" in p:
                k, _, v = p.partition("=")
                params[k] = v
        nodes.append(VlessNode(
            address=host,
            port=port,
            uuid=uuid,
            network=params.get("type", "tcp"),
            security=params.get("security", "none"),
            flow=params.get("flow", ""),
            sni=params.get("sni", ""),
            fp=params.get("fp", "chrome"),
            pbk=params.get("pbk", ""),
            sid=params.get("sid", ""),
            name=re.sub(r'[^\x00-\x7f]', '', (desc or "")).strip(),
        ))
    return nodes


def parse_trojan(text: str) -> list[TrojanNode]:
    nodes = []
    # trojan://PASSWORD@HOST:PORT?params#description
    pat = re.compile(
        r'trojan://([^@]+)@([^:]+):(\d+)(?:\?(.+?))?(?:#(.+))?$'
    )
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("trojan://"):
            continue
        m = pat.match(line)
        if not m:
            continue
        pwd, host, port, params_str, desc = m.groups()
        params = {}
        for p in (params_str or "").split("&"):
            if "=" in p:
                k, _, v = p.partition("=")
                params[k] = v
        nodes.append(TrojanNode(
            address=host,
            port=port,
            password=pwd,
            security=params.get("security", "tls"),
            sni=params.get("sni", ""),
            name=re.sub(r'[^\x00-\x7f]', '', (desc or "")).strip(),
        ))
    return nodes


def parse_ss(text: str) -> list[SSNode]:
    """Parse Shadowsocks nodes.  Supports both old (Base64-whole-URI)
    and new (SIP002 Base64-method-password@host:port) formats."""
    nodes = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("ss://"):
            continue
        try:
            uri = line[len("ss://"):]
            name = ""
            # Strip fragment
            if "#" in uri:
                uri, _, fragment = uri.partition("#")
                name = re.sub(r'[^\x00-\x7f]', '', fragment).strip()
            if "@" in uri:
                # SIP002: Base64(method:password)@host:port
                b64, _, rest = uri.partition("@")
                b64 += "=" * ((4 - len(b64) % 4) % 4)
                method_pwd = base64.b64decode(b64).decode()
                method, _, password = method_pwd.partition(":")
                host, _, port = rest.partition(":")
                nodes.append(SSNode(host, port, method, password, name))
            else:
                # Old format: entire URI is Base64
                uri += "=" * ((4 - len(uri) % 4) % 4)
                decoded = base64.b64decode(uri).decode()
                # method:password@host:port
                m = re.match(r'(.+):(.+)@(.+):(\d+)', decoded)
                if m:
                    method, password, host, port = m.groups()
                    nodes.append(SSNode(host, port, method, password, name))
        except Exception:
            continue
    return nodes


# ── Xray config generators ───────────────────────────────────────────

def _socks_inbound(port: int = 1080, tag: str = "socks-inbound") -> dict:
    return {
        "port": port,
        "listen": "127.0.0.1",
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": False},
        "tag": tag,
    }


def _build_vmess_outbound(node: VmessNode, tag: str) -> dict:
    ob = {
        "protocol": "vmess",
        "tag": tag,
        "settings": {
            "vnext": [{
                "address": node.address,
                "port": node.port,
                "users": [{"id": node.uuid, "security": "auto", "alterId": 0}],
            }]
        },
    }
    ss = _stream_settings(node.network, node.tls, node.host, node.path, node.sni)
    if ss:
        ob["streamSettings"] = ss
    return ob


def _build_vless_outbound(node: VlessNode, tag: str) -> dict:
    ob = {
        "protocol": "vless",
        "tag": tag,
        "settings": {
            "vnext": [{
                "address": node.address,
                "port": node.port,
                "users": [{"id": node.uuid, "flow": node.flow, "encryption": "none"}],
            }]
        },
    }
    ss = _stream_settings_vless(node)
    if ss:
        ob["streamSettings"] = ss
    return ob


def _build_trojan_outbound(node: TrojanNode, tag: str) -> dict:
    ob = {
        "protocol": "trojan",
        "tag": tag,
        "settings": {
            "servers": [{
                "address": node.address,
                "port": node.port,
                "password": node.password,
            }]
        },
    }
    ss = _stream_settings("tcp", node.security, node.sni, "/", node.sni)
    if ss:
        ob["streamSettings"] = ss
    return ob


def _normalize_ss_method(method: str) -> str:
    """Map deprecated SS cipher names to current Xray-supported names."""
    mapping = {
        "chacha20-ietf": "chacha20-ietf-poly1305",
        "chacha20": "chacha20-poly1305",
        "aes-128-ctr": "aes-128-gcm",
        "aes-192-ctr": "aes-192-gcm",
        "aes-256-ctr": "aes-256-gcm",
        "aes-128-cfb": "aes-128-gcm",
        "aes-192-cfb": "aes-192-gcm",
        "aes-256-cfb": "aes-256-gcm",
        "ss": "aes-256-gcm",  # bogus method, default to something valid
    }
    return mapping.get(method, method)


def _build_ss_outbound(node: SSNode, tag: str) -> dict:
    method = _normalize_ss_method(node.method)
    return {
        "protocol": "shadowsocks",
        "tag": tag,
        "settings": {
            "servers": [{
                "address": node.address,
                "port": node.port,
                "method": method,
                "password": node.password,
            }]
        },
    }


def _stream_settings(network, tls, host, path, sni):
    """Build Xray streamSettings for VMess/Trojan."""
    ss = {"network": network or "tcp"}
    if network == "ws":
        ss["wsSettings"] = {"path": path or "/"}
        if host:
            ss["wsSettings"]["headers"] = {"Host": host}
    if tls and tls != "none" and tls != "":
        ss["security"] = "tls"
        ss["tlsSettings"] = {"serverName": sni or host or ""}
    return ss if len(ss) > 1 else None


def _stream_settings_vless(node: VlessNode):
    """Build Xray streamSettings for VLESS, supporting REALITY."""
    ss = {"network": node.network or "tcp"}
    if node.network == "ws":
        ss["wsSettings"] = {"path": "/"}
    if node.security == "reality":
        ss["security"] = "reality"
        ss["realitySettings"] = {
            "serverName": node.sni or node.address,
            "fingerprint": node.fp or "chrome",
            "publicKey": node.pbk or "",
            "shortId": node.sid or "",
        }
    elif node.security == "tls":
        ss["security"] = "tls"
        ss["tlsSettings"] = {
            "serverName": node.sni or node.address,
        }
    return ss if len(ss) > 1 else None


def _xray_config(
    protocol: str,
    nodes: list,
    max_nodes: int = 25,
    active_ports: int = 5,
    base_port: int = 1080,
) -> dict:
    """Generate Xray config with multi-inbound failover.

    Creates `active_ports` SOCKS5 inbounds (ports base_port..base_port+N-1),
    each permanently mapped to a different outbound node.  The crawler
    (or Tor) can switch to the next port when the current node fails —
    no Xray restart needed.

    Remaining nodes are built as extra outbounds (can be activated by
    restarting Xray with a shifted port mapping).
    """
    outbounds = []
    out_tags = []

    builders = {
        "vmess": _build_vmess_outbound,
        "vless": _build_vless_outbound,
        "trojan": _build_trojan_outbound,
        "ss": _build_ss_outbound,
    }
    build = builders[protocol]

    # Build all requested outbounds
    for i, node in enumerate(nodes[:max_nodes]):
        tag = f"{protocol}-{i}"
        try:
            ob = build(node, tag)
            outbounds.append(ob)
            out_tags.append(tag)
        except Exception:
            continue

    if not outbounds:
        raise ValueError(f"No valid {protocol} nodes to generate config")

    # Add direct outbound as last-resort fallback
    outbounds.append({
        "protocol": "freedom",
        "tag": "direct",
        "settings": {},
    })

    # Create multiple inbounds — one per active outbound node
    num_active = min(active_ports, len(out_tags))
    inbounds = []
    routing_rules = []

    for i in range(num_active):
        port = base_port + i
        tag = f"socks-{i}"
        inbounds.append(_socks_inbound(port, tag))
        routing_rules.append({
            "type": "field",
            "inboundTag": [tag],
            "outboundTag": out_tags[i],
        })

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": routing_rules,
        },
    }

    return config


# ── Main ─────────────────────────────────────────────────────────────

def fetch_and_generate(
    protocols: Optional[list[str]] = None,
    max_nodes: int = 25,
    dry_run: bool = False,
    output_dir: str = OUTPUT_DIR,
):
    """Fetch nodes from GitHub and write Xray config files."""
    if protocols is None:
        protocols = ["vmess", "vless", "trojan", "ss"]

    fetchers = {
        "vmess": ("vmess.txt", parse_vmess),
        "vless": ("vless.txt", parse_vless),
        "trojan": ("trojan.txt", parse_trojan),
        "ss": ("shadowsocks.txt", parse_ss),
    }

    for proto in protocols:
        filename, parser = fetchers[proto]
        url = f"{REPO_BASE}/{filename}"

        print(f"\n{'='*60}")
        print(f"[{proto.upper()}] Fetching {url} ...")

        try:
            text = _fetch(url)
        except Exception as e:
            print(f"  SKIP: Failed to fetch — {e}")
            continue

        nodes = parser(text)
        print(f"  Parsed {len(nodes)} nodes")

        if not nodes:
            print(f"  SKIP: No nodes parsed")
            continue

        # Filter to unique addresses
        seen = set()
        unique = []
        for n in nodes:
            key = (n.address, n.port)
            if key not in seen:
                seen.add(key)
                unique.append(n)
        print(f"  Unique: {len(unique)} (deduplicated)")

        # Quick TCP check (first 10 nodes, just for info)
        reachable = 0
        if unique:
            for n in unique[:10]:
                if _quick_tcp_check(n.address, n.port, timeout=3.0):
                    reachable += 1
            print(f"  Quick TCP check (first 10): {reachable}/10 reachable")

        # Generate Xray config
        try:
            config = _xray_config(proto, unique, max_nodes)
        except ValueError as e:
            print(f"  SKIP: {e}")
            continue

        config_path = os.path.join(output_dir, f"xray-{proto}.json")
        config_json = json.dumps(config, indent=2, ensure_ascii=False)

        if dry_run:
            print(f"  [DRY RUN] Would write {len(config_json)} bytes to {config_path}")
            print(f"  Outbounds: {len(config['outbounds'])-1} nodes + direct")
        else:
            os.makedirs(output_dir, exist_ok=True)
            with open(config_path, "w", encoding="utf-8") as f:
                f.write(config_json)
            print(f"  Wrote {config_path} ({len(config_json)} bytes)")
            print(f"  {len(config['outbounds'])-1} nodes + balancer failover")


def main():
    parser = argparse.ArgumentParser(
        description="Fetch free proxy nodes and generate Xray configs with failover"
    )
    parser.add_argument(
        "-p", "--protocol",
        choices=["vmess", "vless", "trojan", "ss"],
        help="Only process one protocol",
    )
    parser.add_argument(
        "-n", "--max-nodes", type=int, default=25,
        help="Max nodes per protocol (default: 25)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print what would be done, don't write files",
    )
    parser.add_argument(
        "-o", "--output-dir", default=OUTPUT_DIR,
        help=f"Output directory (default: {OUTPUT_DIR})",
    )
    args = parser.parse_args()

    protocols = [args.protocol] if args.protocol else None
    fetch_and_generate(
        protocols=protocols,
        max_nodes=args.max_nodes,
        dry_run=args.dry_run,
        output_dir=args.output_dir,
    )


if __name__ == "__main__":
    main()
