#!/bin/bash
set -e

PROXY_HOST="${PROXY_HOST:-v2raya-hysteria2}"
PROXY_PORT="${PROXY_PORT:-20170}"
PROTOCOL="${PROTOCOL:-unknown}"

echo "=== TorCrawl v2rayA Crawler ==="
echo "Protocol: ${PROTOCOL}"
echo "Proxy:    ${PROXY_HOST}:${PROXY_PORT}"

# Configure Tor upstream
cp /etc/tor/torrc /tmp/torrc
sed -i "s/^Socks5Proxy .*/Socks5Proxy ${PROXY_HOST}:${PROXY_PORT}/" /tmp/torrc
grep -q "^Socks5Proxy" /tmp/torrc || echo "Socks5Proxy ${PROXY_HOST}:${PROXY_PORT}" >> /tmp/torrc

mkdir -p /tmp/tor-data
chmod 700 /tmp/tor-data

echo "[1/3] Starting Tor..."
tor -f /tmp/torrc &
TOR_PID=$!

for i in $(seq 1 60); do
    if nc -z 127.0.0.1 9050 2>/dev/null; then
        echo "       Tor SOCKS5 ready"
        break
    fi
    if ! kill -0 ${TOR_PID} 2>/dev/null; then
        echo "ERROR: Tor died"
        exit 1
    fi
    sleep 2
done

echo "[3/3] Starting crawler..."
python /app/docker/crawl_pcap.py
EXIT_CODE=$?

kill ${TOR_PID} 2>/dev/null || true
exit ${EXIT_CODE}
