#!/usr/bin/env python3
"""Build a deduplicated node inventory for the 2026-10-28 recapture.

Sources (host-side):
  - Clash Verge profiles (all *.yaml containing `proxies`)
  - The doggy MIHOMO-UA subscription YAML
  - extra_nodes.yaml (user-provided Trojan nodes + own node + SS nodes)

Outputs (under --out-dir):
  nodes_all.json
  nodes_by_protocol/<protocol>.json
  inventory.md

Only the six wire protocols used by this recapture are kept:
  vless, ss, trojan, anytls, hysteria2, mieru
VMess/TUIC/WireGuard are intentionally excluded.
"""
from __future__ import annotations

import argparse
import base64
import html
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, unquote, urlsplit

import yaml

PROTOCOLS = ["vless", "ss", "trojan", "anytls", "hysteria2", "mieru"]
PROTO_PREFIX = {
    "vless": "vl",
    "ss": "ss",
    "trojan": "tr",
    "anytls": "an",
    "hysteria2": "hy",
    "mieru": "mi",
}
SOURCE_PRIORITY = {"manual": 0, "doggy": 1, "clash": 2, "free": 3}

# Fields that must not be copied verbatim from a profile.
DROP_KEYS = {"name", "dialer-proxy"}


def _load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return yaml.safe_load(f)


def _clean_proxy(proxy: dict, source: str, source_file: str, order: int) -> Optional[dict]:
    """Return a mihomo-compatible proxy dict, or None if unusable."""
    if not isinstance(proxy, dict):
        return None
    ptype = str(proxy.get("type", "")).lower().strip()
    if ptype not in PROTOCOLS:
        return None

    p = {k: v for k, v in proxy.items() if k not in DROP_KEYS}
    p["type"] = ptype

    server = str(p.get("server", "")).strip()
    if not server:
        return None
    p["server"] = server

    try:
        p["port"] = int(p.get("port"))
    except (TypeError, ValueError):
        return None
    if not (0 < p["port"] < 65536):
        return None

    # SS uses `cipher`; some sources call it `method`.
    if ptype == "ss" and "cipher" not in p and "method" in p:
        p["cipher"] = p.pop("method")
    if ptype == "ss" and not p.get("cipher"):
        return None
    # The recapture labels the wire protocol.  SS wrapped in v2ray-plugin /
    # obfs / WebSocket is not plain Shadowsocks on the wire, so exclude it.
    if ptype == "ss" and (
        p.get("plugin")
        or p.get("plugin-opts")
        or p.get("network")
        or p.get("tls")
        or p.get("ws-opts")
        or p.get("grpc-opts")
    ):
        return None

    # Protocol-specific credential sanity.
    if ptype in ("vless", "vmess") and not p.get("uuid"):
        return None
    if ptype in ("trojan", "anytls", "hysteria2") and not p.get("password"):
        return None
    if ptype == "mieru" and not (p.get("username") and p.get("password")):
        return None

    # Enable UDP for protocols that support it; harmless for our TCP crawl.
    if ptype in ("ss", "vless", "trojan", "anytls") and "udp" not in p:
        p["udp"] = True

    p["_source"] = source
    p["_source_file"] = source_file
    p["_orig_name"] = str(proxy.get("name", ""))
    p["_order"] = order
    return p


def _dedupe_key(p: dict) -> tuple:
    # Include the credential and transport, so genuinely different nodes on the
    # same host:port are not collapsed.
    cred = p.get("password") or p.get("uuid") or p.get("username") or ""
    network = p.get("network") or p.get("transport") or ""
    return (
        p["type"],
        p["server"].lower(),
        p["port"],
        str(cred),
        str(network),
    )


# ---------------------------------------------------------------------------
# URI -> mihomo proxy dict (for user-supplied URI lists / free-node lists)
# ---------------------------------------------------------------------------

def _b64_text(value: str) -> str:
    s = unquote(value.strip()).replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "replace")


def _q(params: dict, *keys: str, default: str = "") -> str:
    for key in keys:
        value = params.get(key)
        if value:
            return value[0]
    return default


def _is_true(value: str) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


# Ciphers mihomo can actually initialise.  A malformed URI such as a nested
# "ss://..." userinfo used to produce cipher="ss"; filtering here keeps one bad
# free node from breaking the whole test config.
KNOWN_SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "rc4-md5", "chacha20-ietf", "xchacha20",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-gcm-siv", "aes-256-gcm-siv",
}


def _parse_ss_uri(uri: str) -> Optional[dict]:
    body = uri.split("://", 1)[1]
    fragment = ""
    if "#" in body:
        body, fragment = body.split("#", 1)
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)
    params = parse_qs(query)

    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        userinfo = unquote(userinfo)
        if ":" in userinfo:
            method, password = userinfo.split(":", 1)
        else:
            decoded = _b64_text(userinfo)
            if ":" not in decoded:
                return None
            method, password = decoded.split(":", 1)
    else:
        decoded = _b64_text(body)
        if "@" not in decoded:
            return None
        userinfo, hostport = decoded.rsplit("@", 1)
        if ":" not in userinfo:
            return None
        method, password = userinfo.split(":", 1)

    if ":" not in hostport:
        return None
    host, port_s = hostport.rsplit(":", 1)
    try:
        port = int(port_s)
    except ValueError:
        return None

    method = unquote(method).strip().lower()
    if method not in KNOWN_SS_CIPHERS:
        return None
    proxy = {
        "name": unquote(fragment),
        "type": "ss",
        "server": host.strip("[]"),
        "port": port,
        "cipher": method,
        "password": unquote(password),
        "udp": True,
    }
    # SS-over-WebSocket/TLS/plugin variants are not plain Shadowsocks on the
    # wire; skip them so the "ss" dataset stays a true SS dataset.
    if _q(params, "plugin") or _q(params, "type") or _q(params, "security"):
        return None
    return proxy


def _parse_vless_uri(uri: str) -> Optional[dict]:
    try:
        u = urlsplit(uri)
        host, port = u.hostname, u.port
    except ValueError:
        return None
    if not host or not port or not u.username:
        return None
    q = parse_qs(u.query)
    proxy: dict = {
        "name": unquote(u.fragment),
        "type": "vless",
        "server": host,
        "port": port,
        "uuid": unquote(u.username),
        "udp": True,
    }
    network = _q(q, "type", "network", default="tcp")
    proxy["network"] = network
    security = _q(q, "security", default="none")
    if security in ("tls", "reality"):
        proxy["tls"] = True
        sni = _q(q, "sni", "servername", "peer")
        if sni:
            proxy["servername"] = sni
        fp = _q(q, "fp", "fingerprint")
        if fp:
            proxy["client-fingerprint"] = fp
        alpn = _q(q, "alpn")
        if alpn:
            proxy["alpn"] = [x for x in alpn.split(",") if x]
        if security == "reality":
            pbk = _q(q, "pbk", "publicKey")
            sid = _q(q, "sid", "shortId")
            if pbk:
                proxy["reality-opts"] = {"public-key": pbk}
                if sid:
                    proxy["reality-opts"]["short-id"] = sid
        if _is_true(_q(q, "allowInsecure", "insecure")):
            proxy["skip-cert-verify"] = True
    flow = _q(q, "flow")
    if flow:
        proxy["flow"] = flow
    encryption = _q(q, "encryption")
    if encryption and encryption != "none":
        proxy["encryption"] = encryption

    path = _q(q, "path")
    ws_host = _q(q, "host")
    if network == "ws":
        proxy["ws-opts"] = {"path": path or "/"}
        if ws_host:
            proxy["ws-opts"]["headers"] = {"Host": ws_host}
    elif network == "grpc":
        opts = {"grpc-service-name": _q(q, "serviceName")}
        authority = _q(q, "authority")
        if authority:
            opts["authority"] = authority
        proxy["grpc-opts"] = opts
    elif network in ("xhttp", "splithttp"):
        proxy["network"] = "xhttp"
        opts = {"path": path or "/"}
        if ws_host:
            opts["host"] = ws_host
        mode = _q(q, "mode")
        if mode:
            opts["mode"] = mode
        proxy["xhttp-opts"] = opts
    elif network == "h2":
        proxy["h2-opts"] = {"path": [path or "/"]}
        if ws_host:
            proxy["h2-opts"]["host"] = [ws_host]
    return proxy


def _parse_trojan_uri(uri: str) -> Optional[dict]:
    try:
        u = urlsplit(uri)
        host, port = u.hostname, u.port
    except ValueError:
        return None
    if not host or not port or u.username is None:
        return None
    q = parse_qs(u.query)
    proxy: dict = {
        "name": unquote(u.fragment),
        "type": "trojan",
        "server": host,
        "port": port,
        "password": unquote(u.username),
        "udp": True,
    }
    sni = _q(q, "sni", "peer")
    if sni:
        proxy["sni"] = sni
    if _is_true(_q(q, "allowInsecure", "insecure")):
        proxy["skip-cert-verify"] = True
    network = _q(q, "type", "network", default="tcp")
    if network == "ws":
        proxy["network"] = "ws"
        proxy["ws-opts"] = {"path": _q(q, "path") or "/"}
        host_header = _q(q, "host")
        if host_header:
            proxy["ws-opts"]["headers"] = {"Host": host_header}
    elif network == "grpc":
        proxy["network"] = "grpc"
        proxy["grpc-opts"] = {"grpc-service-name": _q(q, "serviceName")}
    return proxy


def _parse_anytls_uri(uri: str) -> Optional[dict]:
    try:
        u = urlsplit(uri)
        host, port = u.hostname, u.port
    except ValueError:
        return None
    if not host or not port or u.username is None:
        return None
    q = parse_qs(u.query)
    proxy: dict = {
        "name": unquote(u.fragment),
        "type": "anytls",
        "server": host,
        "port": port,
        "password": unquote(u.username),
        "udp": True,
    }
    sni = _q(q, "sni", "peer", "servername")
    if sni:
        proxy["sni"] = sni
    fp = _q(q, "fp", "fingerprint")
    if fp:
        proxy["client-fingerprint"] = fp
    if _is_true(_q(q, "allowInsecure", "insecure")):
        proxy["skip-cert-verify"] = True
    return proxy


def _parse_hy2_uri(uri: str) -> Optional[dict]:
    try:
        u = urlsplit(uri)
        host, port = u.hostname, u.port
    except ValueError:
        return None
    if not host or not port or u.username is None:
        return None
    q = parse_qs(u.query)
    proxy: dict = {
        "name": unquote(u.fragment),
        "type": "hysteria2",
        "server": host,
        "port": port,
        "password": unquote(u.username),
    }
    sni = _q(q, "sni", "peer")
    if sni:
        proxy["sni"] = sni
    if _is_true(_q(q, "allowInsecure", "insecure")):
        proxy["skip-cert-verify"] = True
    ports = _q(q, "mport", "ports", "port-range")
    if ports:
        proxy["ports"] = ports
    hop = _q(q, "hopInterval", "hop-interval", "hop_interval")
    if hop:
        try:
            proxy["hop-interval"] = int(hop)
        except ValueError:
            pass
    pin = _q(q, "pinSHA256", "pinsha256", "fingerprint")
    if pin:
        proxy["fingerprint"] = pin
    obfs = _q(q, "obfs")
    if obfs:
        proxy["obfs"] = obfs
        obfs_password = _q(q, "obfs-password", "obfsPassword")
        if obfs_password:
            proxy["obfs-password"] = obfs_password
    for key, field in (("upmbps", "up"), ("downmbps", "down"), ("up", "up"), ("down", "down")):
        value = _q(q, key)
        if value:
            proxy[field] = value
    return proxy


def parse_uri_line(line: str) -> Optional[dict]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    line = html.unescape(line)
    try:
        if line.startswith("ss://"):
            return _parse_ss_uri(line)
        if line.startswith("vless://"):
            return _parse_vless_uri(line)
        if line.startswith("trojan://"):
            return _parse_trojan_uri(line)
        if line.startswith("anytls://"):
            return _parse_anytls_uri(line)
        if line.startswith(("hysteria2://", "hy2://")):
            if line.startswith("hy2://"):
                line = "hysteria2://" + line.split("://", 1)[1]
            return _parse_hy2_uri(line)
    except Exception:
        return None
    return None


def collect_from_uri_file(path: Path) -> list[tuple[dict, str]]:
    out: list[tuple[dict, str]] = []
    if not path.is_file():
        print(f"[warn] URI file not found: {path}")
        return out
    invalid = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        proxy = parse_uri_line(line)
        if proxy is None:
            if line.strip() and not line.lstrip().startswith("#"):
                invalid += 1
            continue
        out.append((proxy, path.name))
    if invalid:
        print(f"[warn] {path.name}: {invalid} URI line(s) skipped (vmess/truncated/unsupported)")
    return out


def collect_from_clash_profiles(profiles_dir: Path) -> list[tuple[dict, str]]:
    out: list[tuple[dict, str]] = []
    if not profiles_dir.is_dir():
        print(f"[warn] profiles dir not found: {profiles_dir}")
        return out
    order = 0
    for path in sorted(profiles_dir.glob("*.yaml")):
        try:
            doc = _load_yaml(path)
        except Exception as exc:
            print(f"[warn] cannot parse {path.name}: {exc}")
            continue
        if not isinstance(doc, dict):
            continue
        proxies = doc.get("proxies")
        if not isinstance(proxies, list):
            continue
        for proxy in proxies:
            out.append((proxy, path.name))
            order += 1
    return out


def collect_from_subscription(path: Path) -> list[tuple[dict, str]]:
    out: list[tuple[dict, str]] = []
    if not path.is_file():
        print(f"[warn] subscription file not found: {path}")
        return out
    try:
        doc = _load_yaml(path)
    except Exception as exc:
        print(f"[error] cannot parse subscription {path}: {exc}")
        return out
    for proxy in (doc or {}).get("proxies", []) or []:
        out.append((proxy, path.name))
    return out


def collect_from_extra(path: Path) -> list[tuple[dict, str]]:
    out: list[tuple[dict, str]] = []
    if not path.is_file():
        print(f"[warn] extra nodes file not found: {path}")
        return out
    doc = _load_yaml(path) or {}
    for proxy in doc.get("nodes", []) or []:
        out.append((proxy, path.name))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument(
        "--profiles-dir",
        default=os.path.join(
            os.environ.get("APPDATA", ""),
            "io.github.clash-verge-rev.clash-verge-rev",
            "profiles",
        ),
    )
    ap.add_argument(
        "--subscription",
        default="",
        help="Clash-YAML subscription file (mihomo UA recommended)",
    )
    ap.add_argument("--extra", default="", help="extra_nodes.yaml")
    ap.add_argument(
        "--uri-file",
        action="append",
        default=[],
        help="URI list (ss/vless/trojan/anytls/hysteria2); can repeat",
    )
    ap.add_argument(
        "--free-uri-file",
        action="append",
        default=[],
        help="Free-node URI list (lower priority, can repeat)",
    )
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    by_proto_dir = out_dir / "nodes_by_protocol"
    by_proto_dir.mkdir(parents=True, exist_ok=True)
    test_cfg_dir = out_dir / "test_configs"
    test_cfg_dir.mkdir(parents=True, exist_ok=True)

    raw: list[tuple[dict, str, str, int]] = []  # proxy, source, source_file, order

    extra_path = Path(args.extra) if args.extra else out_dir / "extra_nodes.yaml"
    for proxy, source_file in collect_from_extra(extra_path):
        raw.append((proxy, "manual", source_file, len(raw)))

    for uri_file in args.uri_file:
        for proxy, source_file in collect_from_uri_file(Path(uri_file)):
            raw.append((proxy, "manual", source_file, len(raw)))

    for uri_file in args.free_uri_file:
        for proxy, source_file in collect_from_uri_file(Path(uri_file)):
            raw.append((proxy, "free", source_file, len(raw)))

    if args.subscription:
        for proxy, source_file in collect_from_subscription(Path(args.subscription)):
            raw.append((proxy, "doggy", source_file, len(raw)))

    for proxy, source_file in collect_from_clash_profiles(Path(args.profiles_dir)):
        raw.append((proxy, "clash", source_file, len(raw)))

    cleaned: list[dict] = []
    skipped = 0
    for proxy, source, source_file, order in raw:
        p = _clean_proxy(proxy, source, source_file, order)
        if p is None:
            skipped += 1
            continue
        cleaned.append(p)

    # Deduplicate; keep the highest-priority source.
    cleaned.sort(key=lambda p: (SOURCE_PRIORITY[p["_source"]], p["_order"]))
    seen: set[tuple] = set()
    unique: list[dict] = []
    duplicates = 0
    for p in cleaned:
        key = _dedupe_key(p)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        unique.append(p)

    # Assign stable, URL-safe IDs and group by protocol.
    counters = {t: 0 for t in PROTOCOLS}
    grouped: dict[str, list[dict]] = {t: [] for t in PROTOCOLS}
    for p in unique:
        t = p["type"]
        counters[t] += 1
        p["_id"] = f"{PROTO_PREFIX[t]}{counters[t]:04d}"
        p["name"] = p["_id"]
        grouped[t].append(p)

    all_nodes = [n for t in PROTOCOLS for n in grouped[t]]
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "protocols": PROTOCOLS,
        "counts": {t: len(grouped[t]) for t in PROTOCOLS},
        "total": len(all_nodes),
        "skipped_invalid": skipped,
        "duplicates": duplicates,
        "sources": {
            "profiles_dir": str(args.profiles_dir),
            "subscription": str(args.subscription),
            "extra": str(extra_path),
            "uri_files": [str(p) for p in args.uri_file],
            "free_uri_files": [str(p) for p in args.free_uri_file],
        },
    }
    (out_dir / "nodes_all.json").write_text(
        json.dumps({"meta": meta, "nodes": all_nodes}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    for t in PROTOCOLS:
        (by_proto_dir / f"{t}.json").write_text(
            json.dumps(grouped[t], ensure_ascii=False, indent=2), encoding="utf-8"
        )

    # Test configs: one mihomo config per protocol with all nodes.
    for t in PROTOCOLS:
        cfg = {
            "mixed-port": 17890,
            "allow-lan": False,
            "mode": "rule",
            "log-level": "warning",
            "external-controller": "0.0.0.0:19090",
            "secret": "",
            "unified-delay": True,
            "dns": {
                "enable": True,
                "ipv6": False,
                "default-nameserver": ["223.5.5.5"],
                "nameserver": ["223.5.5.5", "119.29.29.29"],
            },
            "proxies": grouped[t],
            "proxy-groups": [
                {
                    "name": "TEST",
                    "type": "select",
                    "proxies": [n["_id"] for n in grouped[t]],
                }
            ],
            "rules": ["MATCH,TEST"],
        }
        (test_cfg_dir / f"{t}.json").write_text(
            json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    # Human-readable inventory.
    lines = [
        "# Node inventory (2026-10-28 recapture)",
        "",
        f"- Generated: {meta['generated_at']}",
        f"- Total unique nodes: **{meta['total']}**",
        f"- Invalid/skipped: {skipped}",
        f"- Duplicates removed: {duplicates}",
        "",
        "| Protocol | Nodes |",
        "|---|---:|",
    ]
    for t in PROTOCOLS:
        lines.append(f"| {t} | {len(grouped[t])} |")
    lines += ["", "## Sources", ""]
    for t in PROTOCOLS:
        src_counts: dict[str, int] = {}
        for n in grouped[t]:
            src_counts[n["_source"]] = src_counts.get(n["_source"], 0) + 1
        lines.append(f"- **{t}**: " + ", ".join(
            f"{k}={v}" for k, v in sorted(src_counts.items())
        ))
    (out_dir / "inventory.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(meta, ensure_ascii=False, indent=2))
    print(f"[ok] wrote {out_dir / 'nodes_all.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
