#!/bin/bash
# =============================================================================
# TorCrawl Docker Entrypoint
# Starts: Xray (front proxy) → Tor → Crawler
#
# Environment variables:
#   PROTOCOL      - Proxy protocol name (vmess/vless/trojan/ss) for logging
#   CRAWL_URL     - Target URL to crawl
#   CRAWL_DEPTH   - Crawl depth (default: 1)
#   CRAWL_PAUSE   - Pause between requests in seconds (default: 2)
#   EXTRA_ARGS    - Additional arguments to pass to torcrawl.py
#   SKIP_TOR_CHECK - Set to 1 to skip Tor connectivity verification
# =============================================================================
set -e

PROTOCOL="${PROTOCOL:-unknown}"
CRAWL_URL="${CRAWL_URL:-https://check.torproject.org}"
CRAWL_DEPTH="${CRAWL_DEPTH:-1}"
CRAWL_PAUSE="${CRAWL_PAUSE:-2}"

echo "╔══════════════════════════════════════════╗"
echo "║     TorCrawl Docker Container           ║"
echo "╠══════════════════════════════════════════╣"
echo "║ Protocol : ${PROTOCOL}"
echo "║ Target   : ${CRAWL_URL}"
echo "║ Depth    : ${CRAWL_DEPTH}"
echo "║ Pause    : ${CRAWL_PAUSE}s"
echo "╚══════════════════════════════════════════╝"

# -------------------------------------------------------------------
# 0. Fetch fresh nodes from GitHub (optional, controlled by env var)
# -------------------------------------------------------------------
if [ "${FETCH_NODES:-1}" = "1" ] && [ -f /app/docker/fetch_nodes.py ]; then
    echo ""
    echo "[0/3] Fetching fresh proxy nodes..."
    python /app/docker/fetch_nodes.py -p "${PROTOCOL}" -n "${MAX_NODES:-15}" -o /tmp/xray-config
    # If fetch succeeded, use the fresh config
    if [ -f "/tmp/xray-config/xray-${PROTOCOL}.json" ]; then
        cp "/tmp/xray-config/xray-${PROTOCOL}.json" /etc/xray/config.json
        echo "       Using freshly fetched nodes"
    else
        echo "       WARNING: Fetch failed, using baked-in config"
    fi
fi

# -------------------------------------------------------------------
# 1. Start Xray (front proxy - connects to remote via protocol)
# -------------------------------------------------------------------
echo ""
echo "[1/3] Starting Xray (protocol: ${PROTOCOL})..."

if [ ! -f /etc/xray/config.json ]; then
    echo "ERROR: /etc/xray/config.json not found!"
    echo "Mount your Xray config to /etc/xray/config.json"
    exit 1
fi

xray run -c /etc/xray/config.json &
XRAY_PID=$!

# Wait for Xray SOCKS5 inbound to be ready
for i in $(seq 1 15); do
    if nc -z 127.0.0.1 1080 2>/dev/null; then
        echo "       ✓ Xray SOCKS5 inbound ready (127.0.0.1:1080)"
        break
    fi
    if [ $i -eq 15 ]; then
        echo "ERROR: Xray failed to start within 30 seconds."
        echo "Last Xray logs:"
        cat /tmp/xray.log 2>/dev/null || true
        exit 1
    fi
    sleep 2
done

# -------------------------------------------------------------------
# 2. Start Tor with Xray port failover
#    Tries each Xray inbound port (1080..1084) until Tor bootstraps.
#    Each port maps to a different proxy node — if one node is down
#    or blocking Tor TLS, we rotate to the next.
# -------------------------------------------------------------------
echo "[2/3] Starting Tor (with node failover)..."

if [ ! -f /etc/tor/torrc ]; then
    echo "ERROR: /etc/tor/torrc not found!"
    exit 1
fi

# Copy torrc to writable location (mounted configs may be read-only)
cp /etc/tor/torrc /tmp/torrc
TORRC_PATH=/tmp/torrc

mkdir -p /tmp/tor-data
chmod 700 /tmp/tor-data

XRAY_BASE_PORT=1080
XRAY_MAX_PORTS=5
TOR_BOOTSTRAP_TIMEOUT=60  # seconds to wait per port

# Count actually available Xray ports
AVAILABLE_PORTS=0
for p in $(seq 0 $((XRAY_MAX_PORTS - 1))); do
    if nc -z 127.0.0.1 $((XRAY_BASE_PORT + p)) 2>/dev/null; then
        AVAILABLE_PORTS=$((AVAILABLE_PORTS + 1))
    fi
done
echo "       Xray ports available: ${AVAILABLE_PORTS} (checking ${XRAY_BASE_PORT}-$((XRAY_BASE_PORT + XRAY_MAX_PORTS - 1)))"

TOR_READY=0
USED_PORT=""

for port_idx in $(seq 0 $((XRAY_MAX_PORTS - 1))); do
    XRAY_PORT=$((XRAY_BASE_PORT + port_idx))

    # Verify this Xray inbound is alive
    if ! nc -z 127.0.0.1 ${XRAY_PORT} 2>/dev/null; then
        echo "       Xray port ${XRAY_PORT} not listening, skipping"
        continue
    fi

    echo "       Trying Xray port ${XRAY_PORT} (node #${port_idx})..."

    # Update torrc Socks5Proxy to point to this Xray port
    if grep -q "^Socks5Proxy" ${TORRC_PATH}; then
        sed -i "s/^Socks5Proxy .*/Socks5Proxy 127.0.0.1:${XRAY_PORT}/" ${TORRC_PATH}
    else
        echo "Socks5Proxy 127.0.0.1:${XRAY_PORT}" >> ${TORRC_PATH}
    fi

    # Start Tor
    tor -f ${TORRC_PATH} &
    TOR_PID=$!

    # Wait for bootstrap
    PORT_READY=0
    START_TIME=$(date +%s)
    while true; do
        ELAPSED=$(($(date +%s) - START_TIME))

        # Check if Tor SOCKS5 port is open
        if [ $PORT_READY -eq 0 ] && nc -z 127.0.0.1 9050 2>/dev/null; then
            PORT_READY=1
            echo "       ✓ Tor SOCKS5 port open (127.0.0.1:9050)"
        fi

        # Check if Tor process died
        if ! kill -0 ${TOR_PID} 2>/dev/null; then
            echo "       ✗ Tor process died on port ${XRAY_PORT}"
            break
        fi

        # Check bootstrap progress from Tor logs
        BOOTSTRAP_PCT=$(grep -oP 'Bootstrapped \K\d+' /tmp/tor-data/log 2>/dev/null | tail -1 || echo 0)
        if [ "${BOOTSTRAP_PCT:-0}" -ge 50 ] 2>/dev/null; then
            TOR_READY=1
            USED_PORT=${XRAY_PORT}
            echo "       ✓ Tor bootstrapped ${BOOTSTRAP_PCT}% on port ${XRAY_PORT}"
            break 2  # break out of both loops
        fi

        # Timeout for this port
        if [ $ELAPSED -ge $TOR_BOOTSTRAP_TIMEOUT ]; then
            echo "       ✗ Tor bootstrap timeout (${ELAPSED}s) on port ${XRAY_PORT}"
            break
        fi

        sleep 3
    done

    # Kill Tor before trying next port
    kill ${TOR_PID} 2>/dev/null || true
    wait ${TOR_PID} 2>/dev/null || true
    sleep 2
done

if [ ${TOR_READY} -eq 0 ]; then
    echo "ERROR: Tor failed to bootstrap on any Xray port (tried ${XRAY_MAX_PORTS})."
    echo "All proxy nodes may be blocking Tor traffic."
    exit 1
fi

# -------------------------------------------------------------------
# 3. Run PCAP Capture Crawler
# -------------------------------------------------------------------
echo "[3/3] Starting PCAP capture crawler..."
echo ""

# Build the command
CMD="python /app/docker/crawl_pcap.py"

echo "Running: ${CMD}"
echo "       Protocol: ${PROTOCOL}"
echo "       Max PCAPs/site: ${MAX_PCAPS:-10}"
echo ""

# Execute PCAP crawler
eval ${CMD}
EXIT_CODE=$?

# -------------------------------------------------------------------
# Done
# -------------------------------------------------------------------
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Crawl finished (exit code: ${EXIT_CODE})"
echo "╚══════════════════════════════════════════╝"

# Graceful shutdown
kill ${TOR_PID} 2>/dev/null || true
kill ${XRAY_PID} 2>/dev/null || true

exit ${EXIT_CODE}
