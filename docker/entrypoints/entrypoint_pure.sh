#!/bin/bash
set -e
PROTOCOL="${PROTOCOL:-unknown}"
echo "=== Pure Proxy Capture (No Tor) ==="
echo "Protocol: ${PROTOCOL}"

# Start Xray
echo "[1/2] Starting Xray..."
xray run -c /etc/xray/config.json &
XRAY_PID=$!
for i in $(seq 1 15); do
    if nc -z 127.0.0.1 1080 2>/dev/null; then echo "       Xray ready (127.0.0.1:1080)"; break; fi
    sleep 2
done

# Run pure crawler
echo "[2/2] Starting pure crawler..."
python /app/docker/crawl_pcap_pure.py
EXIT_CODE=$?

kill $XRAY_PID 2>/dev/null || true
exit $EXIT_CODE
