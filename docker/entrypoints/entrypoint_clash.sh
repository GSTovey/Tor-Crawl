#!/bin/bash
set -e

CLASH_HOST="${CLASH_HOST:-127.0.0.1}"
CLASH_PORT="${CLASH_PORT:-7890}"
PROTOCOL="${PROTOCOL:-unknown}"

echo "=== TorCrawl Clash Crawler ==="
echo "Protocol: ${PROTOCOL}"
echo "Clash:    ${CLASH_HOST}:${CLASH_PORT}"

# Configure Tor to use Clash SOCKS5
cp /etc/tor/torrc /tmp/torrc
sed -i "s/^Socks5Proxy .*/Socks5Proxy ${CLASH_HOST}:${CLASH_PORT}/" /tmp/torrc
grep -q "^Socks5Proxy" /tmp/torrc || echo "Socks5Proxy ${CLASH_HOST}:${CLASH_PORT}" >> /tmp/torrc

mkdir -p /tmp/tor-data
chmod 700 /tmp/tor-data

echo "[1/3] Waiting for Clash SOCKS5..."
for i in $(seq 1 30); do
    if nc -z ${CLASH_HOST} ${CLASH_PORT} 2>/dev/null; then
        echo "       Clash ready"
        break
    fi
    sleep 2
done

echo "[2/3] Starting Tor..."
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
