#!/bin/bash
set -e
PROTOCOL="${PROTOCOL:-unknown}"
echo "=== ToP Dual Capture ==="
echo "Protocol: ${PROTOCOL}"

# Start Xray
xray run -c /etc/xray/config.json &
XRAY_PID=$!
for i in $(seq 1 15); do
    nc -z 127.0.0.1 1080 2>/dev/null && echo "[1/3] Xray ready" && break
    sleep 2
done

# Start Tor
cp /etc/tor/torrc /tmp/torrc
mkdir -p /tmp/tor-data && chmod 700 /tmp/tor-data
tor -f /tmp/torrc &
TOR_PID=$!
for i in $(seq 1 60); do
    nc -z 127.0.0.1 9050 2>/dev/null && echo "[2/3] Tor ready" && break
    sleep 2
done

# Run dual crawler
echo "[3/3] Starting dual capture..."
python /app/docker/crawl_pcap_pairs.py
EXIT_CODE=$?

kill $TOR_PID $XRAY_PID 2>/dev/null || true
exit $EXIT_CODE
