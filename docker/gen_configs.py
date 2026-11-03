#!/usr/bin/env python3
"""Generate Xray configs from proxy_nodes.md with TCP-tested failover nodes."""
import re, base64, json, socket, sys, os
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.dirname(__file__))
from fetch_nodes import (parse_vmess, parse_vless, parse_trojan,
                         _build_vmess_outbound, _build_vless_outbound,
                         _build_trojan_outbound)

with open('../proxy_nodes.md', 'r', encoding='utf-8') as f:
    content = f.read()

sections = {'vmess': '', 'vless': '', 'trojan': ''}
current = None
for line in content.split('\n'):
    if line.startswith('# vmess'): current = 'vmess'; continue
    if line.startswith('# vless'): current = 'vless'; continue
    if line.startswith('# trojan'): current = 'trojan'; continue
    if current: sections[current] += line + '\n'

parsed = {
    'vmess': parse_vmess(sections['vmess']),
    'vless': parse_vless(sections['vless']),
    'trojan': parse_trojan(sections['trojan']),
}

def tcp_ok(host, port, timeout=3):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except: return False

builders = {
    'vmess': _build_vmess_outbound,
    'vless': _build_vless_outbound,
    'trojan': _build_trojan_outbound,
}

for proto, nodes in parsed.items():
    # Dedup
    seen = set()
    unique = []
    for n in nodes:
        key = (n.address, n.port)
        if key not in seen:
            seen.add(key)
            unique.append(n)

    # VLESS: skip REALITY
    if proto == 'vless':
        unique = [n for n in unique if n.security != 'reality']

    # TCP test
    good = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(tcp_ok, n.address, n.port): n for n in unique[:50]}
        for f in as_completed(futures):
            if f.result():
                good.append(futures[f])

    print(f'{proto}: {len(good)}/{len(unique[:50])} TCP-reachable')

    # Build outbounds (max 5)
    outbounds = []
    for i, node in enumerate(good[:5]):
        try:
            ob = builders[proto](node, f'{proto}-{i}')
            outbounds.append(ob)
        except Exception as e:
            print(f'  build error node {i}: {e}')

    if not outbounds:
        print(f'  SKIP {proto}: no outbounds')
        continue

    outbounds.append({'protocol': 'freedom', 'tag': 'direct', 'settings': {}})

    # Multi-inbound for failover
    inbounds = []
    rules = []
    for i in range(len(outbounds) - 1):
        port = 1080 + i
        tag = f'socks-{i}'
        inbounds.append({
            'port': port, 'listen': '127.0.0.1', 'protocol': 'socks',
            'settings': {'auth': 'noauth', 'udp': False}, 'tag': tag
        })
        rules.append({'type': 'field', 'inboundTag': [tag], 'outboundTag': f'{proto}-{i}'})

    config = {
        'log': {'loglevel': 'warning'},
        'inbounds': inbounds,
        'outbounds': outbounds,
        'routing': {'domainStrategy': 'AsIs', 'rules': rules}
    }

    path = f'configs/xray-{proto}.json'
    with open(path, 'w') as f:
        json.dump(config, f, indent=2)
    print(f'  -> {path} ({len(inbounds)} inbounds, {len(outbounds)-1} nodes)')

print('Done.')
