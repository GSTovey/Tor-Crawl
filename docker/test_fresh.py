#!/usr/bin/env python3
"""Test fresh nodes, prefer non-TLS/plain to avoid Tor TLS interference."""
import sys, os, json, socket
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.dirname(__file__))
from fetch_nodes import (parse_vmess, parse_ss, parse_vless, parse_trojan,
                         _build_vmess_outbound, _build_ss_outbound,
                         _build_vless_outbound, _build_trojan_outbound)

NODE_DIR = "G:/free-nodes/nodes"

def load(fname):
    with open(f'{NODE_DIR}/{fname}', 'r', encoding='utf-8', errors='replace') as f:
        return f.read()

def tcp_ok(host, port, timeout=3.0):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except:
        return False

# VMess + SS
for proto_short, proto_long, fname, parser, builder in [
    ('vmess', 'VMess', 'vmess.txt', parse_vmess, _build_vmess_outbound),
    ('ss', 'SS', 'shadowsocks.txt', parse_ss, _build_ss_outbound),
]:
    text = load(fname)
    nodes = parser(text)
    print(f'{proto_long}: {len(nodes)} parsed')

    # Dedup
    seen, unique = set(), []
    for n in nodes:
        key = (n.address, n.port)
        if key not in seen:
            seen.add(key)
            unique.append(n)
    print(f'  {len(unique)} unique')

    # Categorize by security
    if proto_short == 'vmess':
        plain = [n for n in unique if not n.tls or n.tls == '' or n.tls == 'none']
        tls = [n for n in unique if n.tls and n.tls != 'none']
        print(f'  plain: {len(plain)}, TLS: {len(tls)}')
        # Prefer plain nodes (no TLS layer to interfere with Tor)
        candidates = plain[:25] + tls[:25]
    elif proto_short == 'ss':
        # SS nodes without security=tls in streamSettings
        candidates = unique[:50]
    else:
        candidates = unique[:50]

    # TCP test
    good = []
    with ThreadPoolExecutor(max_workers=25) as ex:
        futures = {ex.submit(tcp_ok, n.address, n.port): n for n in candidates}
        for f in as_completed(futures):
            if f.result():
                good.append(futures[f])
    print(f'  {len(good)}/{len(candidates)} TCP-reachable')

    if proto_short == 'vmess':
        plain_good = [n for n in good if not n.tls or n.tls == '' or n.tls == 'none']
        tls_good = [n for n in good if n.tls and n.tls != 'none']
        print(f'  plain-good: {len(plain_good)}, tls-good: {len(tls_good)}')
        # Use plain nodes first, then TLS as backup
        good = plain_good[:4] + tls_good[:2]

    if not good:
        print(f'  SKIP')
        continue
    good = good[:5]

    # Build config
    outbounds = []
    for i, node in enumerate(good):
        try:
            ob = builder(node, f'{proto_short}-{i}')
            outbounds.append(ob)
        except Exception as e:
            print(f'  build err: {e}')

    outbounds.append({'protocol': 'freedom', 'tag': 'direct', 'settings': {}})
    inbounds, rules = [], []
    for i in range(len(outbounds) - 1):
        port = 1080 + i
        tag = f'socks-{i}'
        inbounds.append({
            'port': port, 'listen': '127.0.0.1', 'protocol': 'socks',
            'settings': {'auth': 'noauth', 'udp': False}, 'tag': tag
        })
        rules.append({'type': 'field', 'inboundTag': [tag], 'outboundTag': f'{proto_short}-{i}'})

    config = {
        'log': {'loglevel': 'warning'},
        'inbounds': inbounds,
        'outbounds': outbounds,
        'routing': {'domainStrategy': 'AsIs', 'rules': rules}
    }
    path = f'configs/xray-{proto_short}.json'
    with open(path, 'w') as f:
        json.dump(config, f, indent=2)
    pg = len(plain_good) if proto_short == 'vmess' else len(good)
    tg = len(tls_good) if proto_short == 'vmess' else 0
    print(f"  -> {path} ({len(inbounds)} nodes: {pg} plain + {tg} TLS)")

print('Done.')
