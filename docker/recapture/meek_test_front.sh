#!/bin/bash
set -u
mihomo -d /tmp/mihomo -f /etc/mihomo/config.json > /tmp/mihomo.log 2>&1 &
MPID=$!
sleep 4
mkdir -p /tmp/tor-data
{
  echo "SocksPort 127.0.0.1:9050"
  echo "Socks5Proxy 127.0.0.1:7890"
  echo "DataDirectory /tmp/tor-data"
  echo "Log notice file /tmp/tor-data/log"
  echo "UseBridges 1"
  echo "ClientTransportPlugin meek_lite exec /usr/local/bin/lyrebird"
  echo "Bridge meek_lite 192.0.2.20:80 url=https://1603026938.rsc.cdn77.org front=${MEEK_FRONT:-www.phpmyadmin.net} utls=HelloRandomizedALPN"
} > /tmp/torrc
tor -f /tmp/torrc > /tmp/tor.log 2>&1 &
TPID=$!
for i in $(seq 1 150); do
  if grep -q 'Bootstrapped 100%' /tmp/tor-data/log 2>/dev/null; then break; fi
  if ! kill -0 $TPID 2>/dev/null; then break; fi
  sleep 1
done
echo '== tor log =='; tail -30 /tmp/tor-data/log 2>/dev/null
echo '== mihomo log =='; tail -10 /tmp/mihomo.log 2>/dev/null
echo '== test =='
python - <<'PY'
import socks,socket,ssl,urllib.request
socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5,'127.0.0.1',9050,rdns=True)
socket.socket=socks.socksocket
socket.getaddrinfo=lambda *a,**k:[(socket.AF_INET,socket.SOCK_STREAM,6,'',(a[0],a[1]))]
for u in ['https://check.torproject.org/api/ip','https://example.com']:
    try:
        with urllib.request.urlopen(u,timeout=20,context=ssl.create_default_context()) as r: print(u,r.status,r.read(200)[:100])
    except Exception as e: print(u,'ERR',repr(e)[:120])
PY
sleep infinity
