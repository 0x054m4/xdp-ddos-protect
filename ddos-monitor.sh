#!/bin/bash
# /usr/local/bin/ddos-monitor.sh
# DDoS Target Monitor - runs as a systemd service

set -euo pipefail

# Auto-detect the primary network interface (default route)
IFACE=$(ip -o route get 8.8.8.8 2>/dev/null | awk '{print $5}')
if [ -z "$IFACE" ]; then
    logger -p daemon.err -t ddos-monitor "FATAL: Could not detect network interface"
    exit 1
fi
INTERVAL=3
LOG="/var/log/ddos-target.log"

THRESHOLD=3000
RECOVERY_THRESHOLD=2000
RECOVERY_HITS=3
CAPTURE_COUNT=10000

STATE_DIR="/tmp/ddos-protected"

# --- Cleanup on exit ---
cleanup() {
    logger -t ddos-monitor "Service stopping, flushing rules..."
    ddos_ctl flush || true
    rm -rf "$STATE_DIR"/*
    exit 0
}
trap cleanup SIGTERM SIGINT SIGHUP

# --- Init ---
mkdir -p "$STATE_DIR"
logger -t ddos-monitor "Clearing previous state..."
ddos_ctl flush || true
rm -f "$STATE_DIR"/*
logger -t ddos-monitor "Monitoring destination IPs on $IFACE..."

# --- Main loop ---
while true; do
    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    TMP_FILE="/tmp/dest_ips.txt"

    # Capture traffic snapshot
    tcpdump -nn -i "$IFACE" -c "$CAPTURE_COUNT" 2>/dev/null | \
        awk '{print $5}' | cut -d'.' -f1-4 | \
        grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
        sort | uniq -c | sort -nr > "$TMP_FILE"

    TOP_COUNT=$(head -n1 "$TMP_FILE" | awk '{print $1}')
    TOP_IP=$(head -n1 "$TMP_FILE" | awk '{print $2}')

    [ -z "$TOP_COUNT" ] && TOP_COUNT=0
    [ -z "$TOP_IP" ] && TOP_IP="none"

    logger -t ddos-monitor "TOP_DEST=$TOP_IP PPS=$TOP_COUNT"

    # Add protection only once
    if (( TOP_COUNT > THRESHOLD )) && [ "$TOP_IP" != "none" ]; then
        if [ ! -f "$STATE_DIR/$TOP_IP" ]; then
            MSG="$TIMESTAMP [ALERT] Targeted DDoS on $TOP_IP ($TOP_COUNT pkts)"
            logger -p daemon.warning -t ddos-monitor "$MSG"
            echo "$MSG" >> "$LOG"

            curl -s -X GET \
                "https://apis.cloudjet.org/interna/servers/trigger_ddos_protection.php?server_ip=$TOP_IP&mode=activate" \
                >/dev/null || logger -t ddos-monitor "WARNING: API activate call failed for $TOP_IP"

            ddos_ctl add "$TOP_IP"
            echo 0 > "$STATE_DIR/$TOP_IP"
        else
            # Reset recovery counter while still under attack
            echo 0 > "$STATE_DIR/$TOP_IP"
        fi
    fi

    # Check currently protected IPs for recovery
    for statefile in "$STATE_DIR"/*; do
        [ -e "$statefile" ] || continue

        PROTECTED_IP=$(basename "$statefile")

        CURRENT_COUNT=$(awk -v ip="$PROTECTED_IP" '$2 == ip {print $1}' "$TMP_FILE")
        [ -z "$CURRENT_COUNT" ] && CURRENT_COUNT=0

        if (( CURRENT_COUNT < RECOVERY_THRESHOLD )); then
            HITS=$(cat "$statefile")
            HITS=$((HITS + 1))
            echo "$HITS" > "$statefile"

            if (( HITS >= RECOVERY_HITS )); then
                MSG="$TIMESTAMP [RECOVERY] Removing protection for $PROTECTED_IP (count=$CURRENT_COUNT)"
                logger -p daemon.info -t ddos-monitor "$MSG"
                echo "$MSG" >> "$LOG"

                curl -s -X GET \
                    "https://apis.cloudjet.org/interna/servers/trigger_ddos_protection.php?server_ip=$PROTECTED_IP&mode=deactivate" \
                    >/dev/null || logger -t ddos-monitor "WARNING: API deactivate call failed for $PROTECTED_IP"

                ddos_ctl del "$PROTECTED_IP"
                rm -f "$statefile"
            fi
        else
            # Still receiving enough traffic, reset recovery counter
            echo 0 > "$statefile"
        fi
    done

    sleep "$INTERVAL"
done
