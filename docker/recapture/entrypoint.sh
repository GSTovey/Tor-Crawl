#!/bin/bash
# Recapture container entrypoint.
#   MODE: pure | top | pairs | nontor
# Starts mihomo (pure/top/pairs), Tor (top/pairs), then capture.py.
set -u

MODE="${MODE:-pure}"
PROTOCOL="${PROTOCOL:-unknown}"
MIHOMO_CONFIG="${MIHOMO_CONFIG:-/etc/mihomo/config.yaml}"
TORRC="${TORRC:-/etc/tor/torrc}"

log() { echo "[entrypoint] $*"; }

cleanup() {
    if [ -n "${TOR_PID:-}" ]; then
        kill "$TOR_PID" 2>/dev/null || true
    fi
    if [ -n "${MIHOMO_PID:-}" ]; then
        kill "$MIHOMO_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT TERM INT

mkdir -p /tmp/tor-data /tmp/mihomo

if [ "$MODE" != "nontor" ]; then
    log "starting mihomo ($MIHOMO_CONFIG)"
    mihomo -d /tmp/mihomo -f "$MIHOMO_CONFIG" > /tmp/mihomo.log 2>&1 &
    MIHOMO_PID=$!
    READY=0
    for _ in $(seq 1 40); do
        if nc -z 127.0.0.1 7890 2>/dev/null; then
            READY=1
            break
        fi
        if ! kill -0 "$MIHOMO_PID" 2>/dev/null; then
            log "ERROR: mihomo died"
            tail -60 /tmp/mihomo.log || true
            exit 3
        fi
        sleep 0.5
    done
    if [ "$READY" != "1" ]; then
        log "ERROR: mihomo did not listen on 7890"
        tail -60 /tmp/mihomo.log || true
        exit 3
    fi
    log "mihomo ready"
fi

if [ "$MODE" = "top" ] || [ "$MODE" = "pairs" ]; then
    log "starting tor ($TORRC)"
    cp "$TORRC" /tmp/torrc
    sed -i "s#^DataDirectory .*#DataDirectory /tmp/tor-data#" /tmp/torrc
    tor -f /tmp/torrc > /tmp/tor.log 2>&1 &
    TOR_PID=$!
    echo "$TOR_PID" > /tmp/tor.pid

    TOR_OK=0
    for _ in $(seq 1 180); do
        if ! kill -0 "$TOR_PID" 2>/dev/null; then
            log "ERROR: tor died"
            tail -80 /tmp/tor-data/log 2>/dev/null || true
            tail -40 /tmp/tor.log || true
            exit 4
        fi
        if grep -q "Bootstrapped 100%" /tmp/tor-data/log 2>/dev/null; then
            TOR_OK=1
            log "tor bootstrapped 100%"
            break
        fi
        if grep -q "Bootstrapped 75%" /tmp/tor-data/log 2>/dev/null \
            && nc -z 127.0.0.1 9050 2>/dev/null; then
            TOR_OK=1
            log "tor bootstrapped 75% (will verify with requests)"
            sleep 5
            break
        fi
        sleep 1
    done

    if [ "$TOR_OK" != "1" ] || ! nc -z 127.0.0.1 9050 2>/dev/null; then
        log "ERROR: tor not ready"
        tail -80 /tmp/tor-data/log 2>/dev/null || true
        exit 4
    fi
    log "tor ready"
fi

log "starting capture mode=$MODE protocol=$PROTOCOL"
python /app/recapture/capture.py
RC=$?
log "capture exited rc=$RC"
exit "$RC"
