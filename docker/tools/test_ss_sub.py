#!/usr/bin/env python3
"""Fetch SS subscription, test nodes, generate Xray config."""
import socket, base64, re, json, os, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request

# Route through Clash
import socks
socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', 7897)
socket.socket = socks.socksocket
socket.getaddrinfo = lambda *a: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (a[0], a[1]))]

url = os.environ.get('SS_SUB_URL', '')
req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
data = urlopen(req, timeout=30).read().decode('utf-8')

raw = base64.b64decode(data).decode('utf-8')
lines = [l.strip() for l in raw.split('\n') if l.strip().startswith('ss://')]
print(f'Parsed: {len(lines)} SS nodes')

nodes = []
for line in lines:
    try:
        uri = line[5:]
        if '@' in uri:
            b64, rest = uri.split('@', 1)
            b64 += '=' * ((4 - len(b64) % 4) % 4)
            mp = base64.b64decode(b64).decode()
            method, pwd = mp.split(':', 1)
            hostport = rest.split('#')[0]
            host, port = hostport.split(':')
            nodes.append((host, int(port), method, pwd))
    except: pass

unique = list({(h,p): (h,p,m,pw) for h,p,m,pw in nodes}.values())
print(f'Unique: {len(unique)}')

def tcp_test(hp):
    try:
        s = socket.create_connection(hp, timeout=3)
        s.close()
        return True
    except: return False

good = []
with ThreadPoolExecutor(max_workers=30) as ex:
    futures = {ex.submit(tcp_test, (h,p)): (h,p,m,pw) for h,p,m,pw in unique}
    for f in as_completed(futures):
        if f.result():
            good.append(futures[f])

print(f'TCP reachable: {len(good)}/{len(unique)}')
for h,p,m,pw in good[:5]:
    print(f'  {h}:{p} {m}')

if not good:
    print('No reachable nodes!')
    sys.exit(1)

# Build Xray config with 5 nodes
outbounds = []
for i, (h, p, m, pw) in enumerate(good[:5]):
    ob = {
        'protocol': 'shadowsocks', 'tag': f'ss-{i}',
        'settings': {'servers': [{'address': h, 'port': p, 'method': m, 'password': pw}]}
    }
    outbounds.append(ob)

outbounds.append({'protocol': 'freedom', 'tag': 'direct', 'settings': {}})

inbounds, rules = [], []
for i in range(len(outbounds) - 1):
    port = 1080 + i
    tag = f'socks-{i}'
    inbounds.append({
        'port': port, 'listen': '127.0.0.1', 'protocol': 'socks',
        'settings': {'auth': 'noauth', 'udp': False}, 'tag': tag
    })
    rules.append({'type': 'field', 'inboundTag': [tag], 'outboundTag': f'ss-{i}'})

config = {
    'log': {'loglevel': 'warning'},
    'inbounds': inbounds,
    'outbounds': outbounds,
    'routing': {'domainStrategy': 'AsIs', 'rules': rules}
}

path = 'configs/xray-ss.json'
with open(path, 'w') as f:
    json.dump(config, f, indent=2)
print(f'-> {path} ({len(inbounds)} nodes)')
