#!/bin/bash
echo "=== Pure Tor Capture ==="
cp /etc/tor/torrc /tmp/torrc
mkdir -p /tmp/tor-data
tor -f /tmp/torrc &
for i in $(seq 1 60); do
    if nc -z 127.0.0.1 9050 2>/dev/null; then echo "Tor ready"; break; fi
    sleep 2
done
python /app/docker/crawl_pcap.py
