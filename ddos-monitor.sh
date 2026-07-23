#!/bin/bash
# /usr/local/bin/ddos-monitor.sh
# DDoS destination-IP monitor for systemd

set -uo pipefail

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

INTERVAL=3

# Packets per second required to activate protection
THRESHOLD=3000

# Protection is removed when traffic stays below this PPS
RECOVERY_THRESHOLD=1000

# Number of consecutive low-traffic intervals before recovery
RECOVERY_HITS=3

LOG="/var/log/ddos-target.log"
STATE_DIR="/tmp/ddos-protected"

API_URL="https://apis.cloudjet.org/interna/servers/trigger_ddos_protection.php"

# Auto-detect interface used by the default route
IFACE=$(
    ip -o route get 8.8.8.8 2>/dev/null |
    awk '{print $5; exit}'
)

if [[ -z "$IFACE" ]]; then
    logger -p daemon.err -t ddos-monitor \
        "FATAL: Could not detect primary network interface"
    exit 1
fi

# -------------------------------------------------------------------
# Functions
# -------------------------------------------------------------------

log_message() {
    local priority="$1"
    shift

    logger -p "$priority" -t ddos-monitor "$*"
}

activate_protection() {
    local ip="$1"

    if ! curl \
        --silent \
        --show-error \
        --fail \
        --max-time 10 \
        --get \
        --data-urlencode "server_ip=$ip" \
        --data-urlencode "mode=activate" \
        "$API_URL" >/dev/null; then

        log_message daemon.warning \
            "WARNING: API activation failed for $ip"
    fi

    if ! ddos_ctl add "$ip"; then
        log_message daemon.err \
            "ERROR: ddos_ctl add failed for $ip"
        return 1
    fi

    return 0
}

deactivate_protection() {
    local ip="$1"

    if ! curl \
        --silent \
        --show-error \
        --fail \
        --max-time 10 \
        --get \
        --data-urlencode "server_ip=$ip" \
        --data-urlencode "mode=deactivate" \
        "$API_URL" >/dev/null; then

        log_message daemon.warning \
            "WARNING: API deactivation failed for $ip"
    fi

    if ! ddos_ctl del "$ip"; then
        log_message daemon.err \
            "ERROR: ddos_ctl del failed for $ip"
        return 1
    fi

    return 0
}

cleanup() {
    log_message daemon.info \
        "Service stopping; flushing DDoS protection rules"

    ddos_ctl flush >/dev/null 2>&1 || true
    rm -rf "${STATE_DIR:?}/"*
    exit 0
}

trap cleanup SIGTERM SIGINT SIGHUP

# -------------------------------------------------------------------
# Initialization
# -------------------------------------------------------------------

mkdir -p "$STATE_DIR"
touch "$LOG"

log_message daemon.info "Clearing previous protection state"

ddos_ctl flush >/dev/null 2>&1 || true
rm -rf "${STATE_DIR:?}/"*

log_message daemon.info \
    "Monitoring incoming IPv4 traffic on interface $IFACE"

# -------------------------------------------------------------------
# Main loop
# -------------------------------------------------------------------

while true; do
    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    TMP_FILE=$(mktemp /tmp/ddos-dest-ips.XXXXXX)

    # Capture incoming IPv4 traffic for exactly INTERVAL seconds.
    #
    # tcpdump destination examples:
    #   1.2.3.4.443:
    #   1.2.3.4:
    #
    # The AWK parser extracts the field after ">", removes the trailing
    # colon, and removes a TCP/UDP port when present.

    timeout --signal=TERM "$INTERVAL" \
        tcpdump \
            -nn \
            -l \
            -Q in \
            -i "$IFACE" \
            ip 2>/dev/null |
    awk '
    {
        for (i = 1; i <= NF; i++) {
            if ($i != ">") {
                continue
            }

            destination = $(i + 1)

            # Remove tcpdump punctuation
            sub(/:$/, "", destination)

            # Address with port:
            # 192.0.2.10.443
            if (destination ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                sub(/\.[0-9]+$/, "", destination)
            }

            # Address without port:
            # 192.0.2.10
            if (destination ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                counts[destination]++
            }

            break
        }
    }

    END {
        for (ip in counts) {
            print counts[ip], ip
        }
    }
    ' |
    sort -nr > "$TMP_FILE"

    # timeout normally exits with 124 after ending the capture.
    # The generated capture file remains valid.

    TOP_PACKETS=$(awk 'NR == 1 {print $1}' "$TMP_FILE")
    TOP_IP=$(awk 'NR == 1 {print $2}' "$TMP_FILE")

    TOP_PACKETS=${TOP_PACKETS:-0}
    TOP_IP=${TOP_IP:-none}

    TOP_PPS=$((TOP_PACKETS / INTERVAL))

    log_message daemon.info \
        "TOP_DEST=$TOP_IP PACKETS=$TOP_PACKETS PPS=$TOP_PPS"

    # ---------------------------------------------------------------
    # Detect every destination above the activation threshold
    # ---------------------------------------------------------------

    while read -r PACKETS DEST_IP; do
        [[ -n "$PACKETS" && -n "$DEST_IP" ]] || continue

        PPS=$((PACKETS / INTERVAL))

        if (( PPS <= THRESHOLD )); then
            # File is sorted descending, so remaining destinations
            # will also be below the threshold.
            break
        fi

        STATE_FILE="$STATE_DIR/$DEST_IP"

        if [[ ! -f "$STATE_FILE" ]]; then
            MSG="$TIMESTAMP [ALERT] Targeted DDoS on $DEST_IP: ${PPS} PPS, ${PACKETS} packets in ${INTERVAL}s"

            log_message daemon.warning "$MSG"
            echo "$MSG" >> "$LOG"

            if activate_protection "$DEST_IP"; then
                echo 0 > "$STATE_FILE"

                log_message daemon.warning \
                    "Protection activated for $DEST_IP"
            fi
        else
            # Attack is still above the activation threshold.
            echo 0 > "$STATE_FILE"
        fi
    done < "$TMP_FILE"

    # ---------------------------------------------------------------
    # Check currently protected destinations for recovery
    # ---------------------------------------------------------------

    for STATE_FILE in "$STATE_DIR"/*; do
        [[ -e "$STATE_FILE" ]] || continue

        PROTECTED_IP=$(basename "$STATE_FILE")

        CURRENT_PACKETS=$(
            awk -v ip="$PROTECTED_IP" '
                $2 == ip {
                    print $1
                    exit
                }
            ' "$TMP_FILE"
        )

        CURRENT_PACKETS=${CURRENT_PACKETS:-0}
        CURRENT_PPS=$((CURRENT_PACKETS / INTERVAL))

        if (( CURRENT_PPS < RECOVERY_THRESHOLD )); then
            HITS=$(cat "$STATE_FILE" 2>/dev/null)
            HITS=${HITS:-0}
            HITS=$((HITS + 1))

            echo "$HITS" > "$STATE_FILE"

            log_message daemon.info \
                "Recovery check for $PROTECTED_IP: PPS=$CURRENT_PPS hit=$HITS/$RECOVERY_HITS"

            if (( HITS >= RECOVERY_HITS )); then
                MSG="$TIMESTAMP [RECOVERY] Removing protection for $PROTECTED_IP: ${CURRENT_PPS} PPS"

                log_message daemon.info "$MSG"
                echo "$MSG" >> "$LOG"

                if deactivate_protection "$PROTECTED_IP"; then
                    rm -f "$STATE_FILE"

                    log_message daemon.info \
                        "Protection removed for $PROTECTED_IP"
                fi
            fi
        else
            # Traffic remains high enough to keep protection active.
            echo 0 > "$STATE_FILE"
        fi
    done

    rm -f "$TMP_FILE"
done
