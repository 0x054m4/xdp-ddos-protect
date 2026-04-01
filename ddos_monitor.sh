#!/bin/bash
# ─────────────────────────────────────────────────────────────────────
# ddos_monitor — Real-time traffic monitor for XDP DDoS protection
#
# Reads the BPF rate_limit_map to show per-IP traffic stats,
# top attackers, and alerts when thresholds are exceeded.
#
# Usage:
#   ddos_monitor                  # Default: refresh every 5s, alert at 200 pps
#   ddos_monitor -i 2             # Refresh every 2 seconds
#   ddos_monitor -t 500           # Alert threshold: 500 packets/window
#   ddos_monitor -i 3 -t 100     # Combined
#   ddos_monitor --once           # Single snapshot, no loop
#   ddos_monitor --log            # Also append alerts to /var/log/ddos_monitor.log
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────
INTERVAL=5
ALERT_THRESHOLD=200
ONCE=false
LOG_ENABLED=false
LOG_FILE="/var/log/ddos_monitor.log"
BPFTOOL="/usr/sbin/bpftool"
TOP_ATTACKERS=10

# ── Colors ───────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
DIM='\033[0;90m'
RESET='\033[0m'
BOLD='\033[1m'

# ── Parse arguments ──────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--interval)  INTERVAL="$2"; shift 2 ;;
        -t|--threshold) ALERT_THRESHOLD="$2"; shift 2 ;;
        --once)         ONCE=true; shift ;;
        --log)          LOG_ENABLED=true; shift ;;
        -h|--help)
            echo "Usage: $0 [-i SECONDS] [-t THRESHOLD] [--once] [--log]"
            echo ""
            echo "  -i, --interval   Refresh interval in seconds (default: 5)"
            echo "  -t, --threshold  Packets/window to trigger alert (default: 200)"
            echo "  --once           Single snapshot, then exit"
            echo "  --log            Append alerts to $LOG_FILE"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Preflight checks ────────────────────────────────────────────────
if [ ! -x "$BPFTOOL" ]; then
    echo "Error: bpftool not found at $BPFTOOL"
    exit 1
fi

if ! $BPFTOOL map show 2>/dev/null | grep -q 'rate_limit_map'; then
    echo "Error: rate_limit_map not found. Is the XDP program loaded?"
    exit 1
fi

# ── Helper: convert hex IP to dotted quad ────────────────────────────
# The composite key is (src_ip_nbo << 32) | dst_ip_nbo
# bpftool dumps keys as hex bytes
hex_to_ip() {
    # Takes 4 hex bytes like "0a 00 00 01" → "10.0.0.1"
    printf "%d.%d.%d.%d" "0x$1" "0x$2" "0x$3" "0x$4"
}

# ── Helper: log alert ───────────────────────────────────────────────
log_alert() {
    local msg="$1"
    if $LOG_ENABLED; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') $msg" >> "$LOG_FILE"
    fi
}

# ── Get protected IPs ───────────────────────────────────────────────
get_protected_ips() {
    if [ -e /sys/fs/bpf/protected_ips ]; then
        ddos_ctl list 2>/dev/null | grep '^ ' | awk '{print $1}' || true
    fi
}

# ── Main monitoring function ─────────────────────────────────────────
do_snapshot() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Dump the rate_limit_map
    # Format: key (8 bytes hex) → value (8 bytes timestamp + 4 bytes count)
    local raw_dump
    raw_dump=$($BPFTOOL map dump name rate_limit_map 2>/dev/null) || {
        echo "Warning: could not dump rate_limit_map"
        return
    }

    # Parse the dump into per-destination and per-source stats
    # bpftool outputs JSON-ish format, parse with awk
    local tmpfile
    tmpfile=$(mktemp /tmp/ddos_mon.XXXXXX)

    echo "$raw_dump" | python3 -c '
import sys, json, struct, socket

try:
    data = json.load(sys.stdin)
except:
    sys.exit(0)

if not isinstance(data, list):
    sys.exit(0)

# Each entry: {"key": [...8 bytes...], "value": [...12 bytes...]}
# Key: src_ip_nbo (4 bytes) + dst_ip_nbo (4 bytes) — all network byte order
# Value: last_update u64 (8 bytes) + packet_count u32 (4 bytes)

for entry in data:
    if "key" not in entry or "value" not in entry:
        continue
    
    key_bytes = entry["key"]
    val_bytes = entry["value"]
    
    if len(key_bytes) < 8 or len(val_bytes) < 12:
        continue
    
    # Parse source IP (first 4 bytes, network byte order)
    src_ip = socket.inet_ntoa(bytes(key_bytes[0:4]))
    # Parse dest IP (next 4 bytes, network byte order)  
    dst_ip = socket.inet_ntoa(bytes(key_bytes[4:8]))
    
    # Parse packet count (bytes 8-11 of value, little-endian u32)
    pkt_count = val_bytes[8] | (val_bytes[9] << 8) | (val_bytes[10] << 16) | (val_bytes[11] << 24)
    
    # Parse last_update (bytes 0-7 of value, little-endian u64)
    ts = 0
    for i in range(8):
        ts |= val_bytes[i] << (i * 8)
    
    print(f"{dst_ip}\t{src_ip}\t{pkt_count}\t{ts}")
' > "$tmpfile" 2>/dev/null || true

    # ── Build per-destination summary ────────────────────────────────
    declare -A dst_total_pkts
    declare -A dst_unique_sources
    declare -A dst_top_source
    declare -A dst_top_source_pkts
    local alert_ips=()

    while IFS=$'\t' read -r dst src pkts ts; do
        [ -z "$dst" ] && continue

        # Accumulate total packets per destination
        dst_total_pkts[$dst]=$(( ${dst_total_pkts[$dst]:-0} + pkts ))

        # Count unique sources per destination
        dst_unique_sources[$dst]=$(( ${dst_unique_sources[$dst]:-0} + 1 ))

        # Track top source per destination
        if [ "${pkts}" -gt "${dst_top_source_pkts[$dst]:-0}" ]; then
            dst_top_source[$dst]="$src"
            dst_top_source_pkts[$dst]="$pkts"
        fi

    done < "$tmpfile"

    rm -f "$tmpfile"

    # ── Get protected IPs ────────────────────────────────────────────
    local protected
    protected=$(get_protected_ips)

    # ── Display ──────────────────────────────────────────────────────
    clear
    echo -e "${BOLD}${WHITE}═══════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${WHITE}  XDP DDoS Monitor${RESET}  ${DIM}$timestamp  │  Refresh: ${INTERVAL}s  │  Alert: >${ALERT_THRESHOLD} pps${RESET}"
    echo -e "${BOLD}${WHITE}═══════════════════════════════════════════════════════════════════════${RESET}"
    echo ""

    # Protected IPs status
    echo -e "${BOLD}${CYAN}  Protected IPs:${RESET}"
    if [ -n "$protected" ]; then
        echo "$protected" | while read -r pip; do
            local total=${dst_total_pkts[$pip]:-0}
            local sources=${dst_unique_sources[$pip]:-0}
            local status_color=$GREEN
            local status_icon="●"

            if [ "$total" -gt "$ALERT_THRESHOLD" ]; then
                status_color=$RED
                status_icon="▲"
            elif [ "$total" -gt $((ALERT_THRESHOLD / 2)) ]; then
                status_color=$YELLOW
                status_icon="▲"
            fi

            printf "    ${status_color}${status_icon}${RESET}  %-18s ${DIM}│${RESET}  %8s pkts  ${DIM}│${RESET}  %5s sources\n" \
                "$pip" "$total" "$sources"
        done
    else
        echo -e "    ${DIM}(none — use 'ddos_ctl add <IP>' to protect IPs)${RESET}"
    fi

    echo ""
    echo -e "${BOLD}${WHITE}───────────────────────────────────────────────────────────────────────${RESET}"
    echo ""

    # Per-destination breakdown (sorted by total packets, descending)
    echo -e "${BOLD}${WHITE}  Destination IP        Total Pkts    Sources    Top Source (pkts)${RESET}"
    echo -e "${DIM}  ─────────────────────────────────────────────────────────────────${RESET}"

    # Sort destinations by total packets
    local has_traffic=false
    for dst in $(for k in "${!dst_total_pkts[@]}"; do
        echo "${dst_total_pkts[$k]} $k"
    done | sort -rn | awk '{print $2}'); do

        has_traffic=true
        local total=${dst_total_pkts[$dst]}
        local sources=${dst_unique_sources[$dst]}
        local top_src=${dst_top_source[$dst]:-"-"}
        local top_pkts=${dst_top_source_pkts[$dst]:-0}

        local color=$GREEN
        if [ "$total" -gt "$ALERT_THRESHOLD" ]; then
            color=$RED
        elif [ "$total" -gt $((ALERT_THRESHOLD / 2)) ]; then
            color=$YELLOW
        fi

        printf "  ${color}%-22s %10s %10s${RESET}    %-16s ${DIM}(%s)${RESET}\n" \
            "$dst" "$total" "$sources" "$top_src" "$top_pkts"

        # Alert logic
        if [ "$total" -gt "$ALERT_THRESHOLD" ]; then
            alert_ips+=("$dst")
        fi
    done

    if ! $has_traffic; then
        echo -e "  ${DIM}(no traffic recorded yet)${RESET}"
    fi

    echo ""

    # ── Alerts ───────────────────────────────────────────────────────
    if [ ${#alert_ips[@]} -gt 0 ]; then
        echo -e "${BOLD}${RED}  ⚠  ALERTS${RESET}"
        echo -e "${DIM}  ─────────────────────────────────────────────────────────────────${RESET}"
        for aip in "${alert_ips[@]}"; do
            local msg="ALERT: $aip receiving ${dst_total_pkts[$aip]} pkts from ${dst_unique_sources[$aip]} sources (top: ${dst_top_source[$aip]} @ ${dst_top_source_pkts[$aip]} pkts)"
            echo -e "  ${RED}▲ $msg${RESET}"
            log_alert "$msg"
        done
        echo ""
    fi

    # ── Top Attackers (across all destinations) ──────────────────────
    echo -e "${BOLD}${WHITE}  Top Sources (across all destinations)${RESET}"
    echo -e "${DIM}  ─────────────────────────────────────────────────────────────────${RESET}"

    # Re-read and aggregate by source
    $BPFTOOL map dump name rate_limit_map 2>/dev/null | python3 -c '
import sys, json, socket

try:
    data = json.load(sys.stdin)
except:
    sys.exit(0)

if not isinstance(data, list):
    sys.exit(0)

src_totals = {}
src_dests = {}

for entry in data:
    if "key" not in entry or "value" not in entry:
        continue
    key_bytes = entry["key"]
    val_bytes = entry["value"]
    if len(key_bytes) < 8 or len(val_bytes) < 12:
        continue

    src_ip = socket.inet_ntoa(bytes(key_bytes[0:4]))
    dst_ip = socket.inet_ntoa(bytes(key_bytes[4:8]))
    pkt_count = val_bytes[8] | (val_bytes[9] << 8) | (val_bytes[10] << 16) | (val_bytes[11] << 24)

    src_totals[src_ip] = src_totals.get(src_ip, 0) + pkt_count
    if src_ip not in src_dests:
        src_dests[src_ip] = set()
    src_dests[src_ip].add(dst_ip)

# Sort by total packets, top N
top = sorted(src_totals.items(), key=lambda x: x[1], reverse=True)[:'"$TOP_ATTACKERS"']
for src, total in top:
    targets = len(src_dests.get(src, set()))
    print(f"{src}\t{total}\t{targets}")
' 2>/dev/null | while IFS=$'\t' read -r src total targets; do
        local color=$GREEN
        if [ "$total" -gt "$ALERT_THRESHOLD" ]; then
            color=$RED
        elif [ "$total" -gt $((ALERT_THRESHOLD / 2)) ]; then
            color=$YELLOW
        fi
        printf "  ${color}%-22s %10s pkts    → %s destination(s)${RESET}\n" \
            "$src" "$total" "$targets"
    done

    echo ""
    echo -e "${DIM}  Press Ctrl+C to exit${RESET}"
}

# ── Run ──────────────────────────────────────────────────────────────
if $ONCE; then
    do_snapshot
else
    trap 'echo -e "\n${GREEN}Monitor stopped.${RESET}"; exit 0' INT TERM
    while true; do
        do_snapshot
        sleep "$INTERVAL"
    done
fi
