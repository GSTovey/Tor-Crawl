#!/bin/bash
echo "=== Tor plugins ==="
ls /usr/lib/*/tor/ 2>/dev/null || echo "no plugins dir"
echo "=== obfs4proxy ==="
which obfs4proxy && obfs4proxy -version
echo "=== webtunnel ==="
which webtunnel 2>/dev/null || apt list --installed 2>/dev/null | grep -i webtunnel || echo "webtunnel not found"
echo "=== tor version ==="
tor --version
