#!/bin/bash
set -u
PROTO="${PROTO:-unknown}"
mihomo -d /tmp/mihomo -f /etc/mihomo/config.yaml > /tmp/mihomo.log 2>&1 &
MPID=$!
for _ in $(seq 1 40); do
    nc -z 127.0.0.1 7890 2>/dev/null && break
    sleep 0.5
done
python /app/recapture/precheck_targets.py \
    --site-list /app/sites/top1000.txt \
    --out "/app/output/reachable_${PROTO}.txt" \
    --protocol "$PROTO" \
    --timeout 6 \
    --workers 12
RC=$?
kill "$MPID" 2>/dev/null || true
exit "$RC"
