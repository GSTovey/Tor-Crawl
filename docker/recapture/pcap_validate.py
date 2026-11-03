#!/usr/bin/env python3
"""Minimal, dependency-free PCAP validator for the recapture pipeline.

It parses classic libpcap files (the format tcpdump writes) and reports enough
TCP/UDP/TLS/QUIC evidence to decide whether a captured request actually
established a working connection:

  * TCP: SYN, SYN+ACK, ACK, bidirectional payload, no RST before payload
  * QUIC/Hysteria2: UDP packets both ways, payload both ways, QUIC long header
  * endpoint sanity: public remote endpoint, no host-Clash 192.168.65.254:7897
  * pair "pre" captures: TCP to 127.0.0.1:7890 with bidirectional payload

Usage:
  python pcap_validate.py --file X.pcap --mode post --protocol vless \
      --ports 443 --json
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable, Optional


def _ip_is_private(ip: str) -> bool:
    if not ip:
        return True
    if ":" in ip:
        low = ip.lower()
        return (
            low == "::1"
            or low.startswith("fe80:")
            or low.startswith("fc")
            or low.startswith("fd")
        )
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return True
    return (
        a == 10
        or a == 127
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or (a == 169 and b == 254)
        or (a == 100 and 64 <= b <= 127)
        or a == 0
        or a >= 224
    )


def _port_allowed(port: int, ranges: Iterable[list[int]]) -> bool:
    for item in ranges:
        if len(item) == 2 and item[0] <= port <= item[1]:
            return True
    return False


def _quic_long_header(payload: bytes) -> bool:
    if len(payload) < 5:
        return False
    b0 = payload[0]
    if (b0 & 0xC0) != 0xC0:  # long form + fixed bit
        return False
    version = int.from_bytes(payload[1:5], "big")
    return version != 0


class Summary:
    def __init__(self) -> None:
        self.pcap_packets = 0
        self.pcap_bytes = 0
        self.ip_packets = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.tcp_syn_c2s = 0
        self.tcp_synack_s2c = 0
        self.tcp_ack_c2s = 0
        self.tcp_rst_c2s = 0
        self.tcp_rst_s2c = 0
        self.tcp_payload_c2s = 0
        self.tcp_payload_s2c = 0
        self.udp_payload_c2s = 0
        self.udp_payload_s2c = 0
        self.udp_packets_c2s = 0
        self.udp_packets_s2c = 0
        self.quic_long_c2s = 0
        self.quic_long_s2c = 0
        self.matched_packets = 0
        self.matched_payload_c2s = 0
        self.matched_payload_s2c = 0
        self.public_remote_seen = False
        self.host_clash_seen = False
        self.first_data_idx: Optional[int] = None
        self.first_rst_idx: Optional[int] = None
        self.remote_endpoints: Counter = Counter()
        self.local_endpoints: Counter = Counter()

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")} | {
            "remote_endpoints": dict(self.remote_endpoints.most_common(10)),
            "local_endpoints": dict(self.local_endpoints.most_common(10)),
        }


def _parse_packet(
    data: bytes,
    linktype: int,
    idx: int,
    mode: str,
    allowed_ports: list[list[int]],
    proxy_port: int,
    allowed_endpoints: list[list],
    s: Summary,
) -> None:
    s.pcap_packets += 1
    s.pcap_bytes += len(data)

    off = 0
    ethertype = None
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return
        ethertype = int.from_bytes(data[12:14], "big")
        off = 14
        # VLAN / QinQ
        while ethertype in (0x8100, 0x88A8, 0x9100) and len(data) >= off + 4:
            ethertype = int.from_bytes(data[off + 2 : off + 4], "big")
            off += 4
    elif linktype == 113:  # Linux cooked SLL
        if len(data) < 16:
            return
        ethertype = int.from_bytes(data[14:16], "big")
        off = 16
    elif linktype == 276:  # Linux cooked SLL2
        if len(data) < 20:
            return
        ethertype = int.from_bytes(data[0:2], "big")
        off = 20
    elif linktype == 0:  # NULL/loopback
        if len(data) < 4:
            return
        family = int.from_bytes(data[0:4], "little")
        if family not in (2, 24, 28, 30):
            return
        off = 4
        # Let the IP version nibble decide below.
        ethertype = 0x0800 if data[off] >> 4 == 4 else 0x86DD
    elif linktype in (12, 101):  # raw IP
        off = 0
        ethertype = 0x0800 if data and data[0] >> 4 == 4 else 0x86DD
    else:
        # Best effort: try raw IP.
        if not data:
            return
        ethertype = 0x0800 if data[0] >> 4 == 4 else 0x86DD
        off = 0

    if ethertype not in (0x0800, 0x86DD):
        return
    if len(data) <= off:
        return
    ip = data[off:]

    src_ip = dst_ip = ""
    proto = 0
    ip_payload = b""
    if ethertype == 0x0800:
        if len(ip) < 20:
            return
        version = ip[0] >> 4
        if version != 4:
            return
        ihl = (ip[0] & 0x0F) * 4
        if ihl < 20 or len(ip) < ihl:
            return
        total_len = int.from_bytes(ip[2:4], "big")
        if total_len < ihl or total_len > len(ip):
            total_len = len(ip)
        proto = ip[9]
        src_ip = ".".join(str(b) for b in ip[12:16])
        dst_ip = ".".join(str(b) for b in ip[16:20])
        ip_payload = ip[ihl:total_len]
    else:
        if len(ip) < 40:
            return
        if ip[0] >> 4 != 6:
            return
        payload_len = int.from_bytes(ip[4:6], "big")
        proto = ip[6]
        src_ip = ":".join(f"{int.from_bytes(ip[i:i+2],'big'):x}" for i in range(8, 24, 2))
        dst_ip = ":".join(f"{int.from_bytes(ip[i:i+2],'big'):x}" for i in range(24, 40, 2))
        ip_payload = ip[40:]
        # Skip common IPv6 extension headers.
        guard = 0
        while proto in (0, 43, 44, 51, 60) and len(ip_payload) >= 8 and guard < 8:
            guard += 1
            if proto == 44:
                ext_len = 8
            elif proto == 51:
                ext_len = (ip_payload[1] + 2) * 4
            else:
                ext_len = (ip_payload[1] + 1) * 8
            if ext_len < 8 or len(ip_payload) < ext_len:
                return
            proto = ip_payload[0]
            ip_payload = ip_payload[ext_len:]
        if payload_len:
            ip_payload = ip_payload[: max(0, payload_len - (len(ip) - len(ip_payload)))]

    if not src_ip or not dst_ip:
        return
    s.ip_packets += 1

    # Parse transport ports once; direction and endpoint matching use them.
    sport = dport = 0
    if proto == 6 and len(ip_payload) >= 20:
        sport = int.from_bytes(ip_payload[0:2], "big")
        dport = int.from_bytes(ip_payload[2:4], "big")
    elif proto == 17 and len(ip_payload) >= 8:
        sport = int.from_bytes(ip_payload[0:2], "big")
        dport = int.from_bytes(ip_payload[2:4], "big")

    # Old mislabelled captures went through host Clash at 192.168.65.254:7897.
    if (dport == 7897 and _ip_is_private(dst_ip)) or (
        sport == 7897 and _ip_is_private(src_ip)
    ):
        s.host_clash_seen = True

    if mode == "pre":
        # Both ends are loopback; the server side is mihomo's SOCKS port.
        if proto not in (6, 17):
            return
        if dport == proxy_port:
            direction = "c2s"
            remote_ip, remote_port = dst_ip, dport
            s.local_endpoints[f"{src_ip}:{sport}"] += 1
        elif sport == proxy_port:
            direction = "s2c"
            remote_ip, remote_port = src_ip, sport
            s.local_endpoints[f"{dst_ip}:{dport}"] += 1
        else:
            return
        matched = True
    else:
        if proto not in (6, 17):
            return
        # Self-hosted proxy endpoint (private Docker IP) support.
        endpoint_c2s = any(
            str(dst_ip) == str(ep[0]) and dport == int(ep[1])
            for ep in allowed_endpoints
        )
        endpoint_s2c = any(
            str(src_ip) == str(ep[0]) and sport == int(ep[1])
            for ep in allowed_endpoints
        )
        if endpoint_c2s or endpoint_s2c:
            direction = "c2s" if endpoint_c2s else "s2c"
            remote_ip, remote_port = (
                (dst_ip, dport) if endpoint_c2s else (src_ip, sport)
            )
            s.public_remote_seen = True
            s.remote_endpoints[f"{remote_ip}:{remote_port}"] += 1
            s.matched_packets += 1
        else:
            src_priv, dst_priv = _ip_is_private(src_ip), _ip_is_private(dst_ip)
            if src_priv and not dst_priv:
                direction = "c2s"
                remote_ip, remote_port = dst_ip, dport
            elif dst_priv and not src_priv:
                direction = "s2c"
                remote_ip, remote_port = src_ip, sport
            elif not src_priv and not dst_priv:
                # Two public endpoints (rare on a container eth0).  Use ports.
                use_dst = not allowed_ports or _port_allowed(dport, allowed_ports)
                direction = "c2s" if use_dst else "s2c"
                remote_ip, remote_port = (dst_ip, dport) if use_dst else (src_ip, sport)
            else:
                # Private-to-private traffic is not the public proxy endpoint;
                # host-Clash cases were flagged above.
                return
            matched = (not _ip_is_private(remote_ip)) and (
                not allowed_ports or _port_allowed(remote_port, allowed_ports)
            )
            if not _ip_is_private(remote_ip):
                s.public_remote_seen = True
            s.remote_endpoints[f"{remote_ip}:{remote_port}"] += 1
            if not matched:
                return
            s.matched_packets += 1

    # TCP
    if proto == 6:
        if len(ip_payload) < 20:
            return
        s.tcp_packets += 1
        data_off = (ip_payload[12] >> 4) * 4
        if data_off < 20 or data_off > len(ip_payload):
            return
        flags = ip_payload[13]
        payload = ip_payload[data_off:]
        plen = len(payload)
        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)
        rst = bool(flags & 0x04)

        if direction == "c2s":
            if syn and not ack:
                s.tcp_syn_c2s += 1
            if ack:
                s.tcp_ack_c2s += 1
            if rst:
                s.tcp_rst_c2s += 1
            if plen:
                s.tcp_payload_c2s += plen
                if mode != "pre":
                    s.matched_payload_c2s += plen
        else:
            if syn and ack:
                s.tcp_synack_s2c += 1
            if rst:
                s.tcp_rst_s2c += 1
            if plen:
                s.tcp_payload_s2c += plen
                if mode != "pre":
                    s.matched_payload_s2c += plen

        if plen and s.first_data_idx is None:
            s.first_data_idx = idx
        if rst and s.first_rst_idx is None:
            s.first_rst_idx = idx
        return

    # UDP
    if proto == 17:
        if len(ip_payload) < 8:
            return
        s.udp_packets += 1
        udp_len = int.from_bytes(ip_payload[4:6], "big")
        payload = ip_payload[8:udp_len] if udp_len >= 8 else ip_payload[8:]
        plen = len(payload)
        is_long = _quic_long_header(payload)
        if direction == "c2s":
            s.udp_packets_c2s += 1
            s.udp_payload_c2s += plen
            if is_long:
                s.quic_long_c2s += 1
            if mode != "pre":
                s.matched_payload_c2s += plen
        else:
            s.udp_packets_s2c += 1
            s.udp_payload_s2c += plen
            if is_long:
                s.quic_long_s2c += 1
            if mode != "pre":
                s.matched_payload_s2c += plen
        if plen and s.first_data_idx is None:
            s.first_data_idx = idx
        return


def parse_pcap(
    path: str | Path,
    mode: str,
    protocol: str,
    allowed_ports: Optional[list[list[int]]] = None,
    allowed_udp: bool = False,
    proxy_port: int = 7890,
    allowed_endpoints: Optional[list[list]] = None,
) -> dict:
    allowed_ports = allowed_ports or []
    allowed_endpoints = allowed_endpoints or []
    s = Summary()
    data = Path(path).read_bytes()
    if len(data) < 24:
        return {"valid": False, "reasons": ["pcap_too_small"], "summary": s.as_dict()}

    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        return {"valid": False, "reasons": ["bad_pcap_magic"], "summary": s.as_dict()}

    try:
        _, _, _, _, _, _, linktype = struct.unpack(endian + "IHHIIII", data[:24])
    except struct.error:
        return {"valid": False, "reasons": ["bad_pcap_header"], "summary": s.as_dict()}

    off = 24
    idx = 0
    while off + 16 <= len(data):
        try:
            _, _, incl_len, _ = struct.unpack(endian + "IIII", data[off : off + 16])
        except struct.error:
            break
        off += 16
        if incl_len > len(data) - off:
            break
        packet = data[off : off + incl_len]
        off += incl_len
        idx += 1
        try:
            _parse_packet(
                packet,
                linktype,
                idx,
                mode,
                allowed_ports,
                proxy_port,
                allowed_endpoints,
                s,
            )
        except Exception:
            # A malformed packet must not abort the whole file.
            continue

    reasons: list[str] = []
    if s.pcap_bytes < 500:
        reasons.append("pcap_bytes_lt_500")
    if s.host_clash_seen:
        reasons.append("host_clash_7897_seen")

    udp_mode = protocol == "hysteria2" or (
        protocol == "mieru" and allowed_udp and s.udp_packets > s.tcp_packets
    )
    if mode == "pre":
        # Long-lived Tor/proxy connections may not show a SYN in the window;
        # bidirectional SOCKS payload is the meaningful evidence.
        if s.tcp_packets == 0:
            reasons.append("pre_no_tcp")
        if s.tcp_payload_c2s <= 0:
            reasons.append("pre_no_c2s_payload")
        if s.tcp_payload_s2c <= 0:
            reasons.append("pre_no_s2c_payload")
        if s.tcp_payload_c2s + s.tcp_payload_s2c < 100:
            reasons.append("pre_tcp_payload_lt_100")
    elif udp_mode:
        if protocol == "hysteria2" and s.udp_packets == 0:
            reasons.append("hy2_no_udp")
        if s.udp_packets_c2s < 2:
            reasons.append("udp_c2s_packets_lt_2")
        if s.udp_packets_s2c < 2:
            reasons.append("udp_s2c_packets_lt_2")
        if s.udp_payload_c2s < 200:
            reasons.append("udp_c2s_bytes_lt_200")
        if s.udp_payload_s2c < 200:
            reasons.append("udp_s2c_bytes_lt_200")
        # Do not require a QUIC long header here: hysteria2 commonly reuses a
        # long-lived QUIC session, so a one-request window may only contain
        # short-header packets.  Bidirectional UDP payload is the evidence.
    else:
        # Proxy connections (especially Tor over a proxy) can be long-lived and
        # therefore SYN-less inside a one-request capture window.  Require
        # bidirectional payload; require a full handshake only for direct.
        if s.tcp_payload_c2s <= 0:
            reasons.append("no_c2s_payload")
        if s.tcp_payload_s2c <= 0:
            reasons.append("no_s2c_payload")
        if s.tcp_payload_c2s + s.tcp_payload_s2c < 200:
            reasons.append("tcp_payload_lt_200")
        if (
            s.first_rst_idx is not None
            and s.first_data_idx is not None
            and s.first_rst_idx < s.first_data_idx
        ):
            reasons.append("rst_before_data")
        if mode == "nontor":
            if s.tcp_syn_c2s < 1:
                reasons.append("nontor_no_syn")
            if s.tcp_synack_s2c < 1:
                reasons.append("nontor_no_synack")

    if mode in ("post", "nontor"):
        if not s.public_remote_seen:
            reasons.append("no_public_remote")
        if s.matched_packets < 2:
            reasons.append("matched_packets_lt_2")
        if s.matched_payload_c2s <= 0:
            reasons.append("matched_no_c2s_payload")
        if s.matched_payload_s2c <= 0:
            reasons.append("matched_no_s2c_payload")
        if mode == "nontor" and s.host_clash_seen:
            reasons.append("nontor_uses_proxy")

    return {
        "valid": not reasons,
        "reasons": reasons,
        "summary": s.as_dict(),
        "mode": mode,
        "protocol": protocol,
        "allowed_ports": allowed_ports,
        "udp_mode": udp_mode,
    }


def _parse_port_ranges(text: str) -> list[list[int]]:
    out: list[list[int]] = []
    for chunk in (text or "").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            out.append([int(a), int(b)])
        else:
            out.append([int(chunk), int(chunk)])
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True)
    ap.add_argument("--mode", choices=["pre", "post", "nontor"], default="post")
    ap.add_argument("--protocol", default="unknown")
    ap.add_argument("--ports", default="", help="e.g. 443,40000-50000")
    ap.add_argument("--udp", action="store_true")
    ap.add_argument("--proxy-port", type=int, default=7890)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    result = parse_pcap(
        args.file,
        args.mode,
        args.protocol,
        _parse_port_ranges(args.ports),
        args.udp,
        args.proxy_port,
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(json.dumps({k: result[k] for k in ("valid", "reasons")}, ensure_ascii=False))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
