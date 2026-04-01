#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

#define THRESHOLD 350              // Max packets per second
#define TIME_WINDOW_NS 1000000000ULL  // 1 second
#define INACTIVE_TIMEOUT (300ULL * TIME_WINDOW_NS) // 5 minutes

struct rate_limit_entry {
    __u64 last_update;
    __u32 packet_count;
};

// ── Maps ────────────────────────────────────────────────────────────────

// Set of destination IPs to protect (value is unused, just a flag)
// Managed from userspace — add/remove IPs without restarting the program
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);       // Destination IP (network byte order)
    __type(value, __u8);      // Dummy value (1 = active)
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // Pin so userspace can access
} protected_ips SEC(".maps");

// Per-source-IP rate limiter (only for traffic hitting protected IPs)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);       // Composite key: (src_ip << 32) | dst_ip
    __type(value, struct rate_limit_entry);
} rate_limit_map SEC(".maps");

// ── Helpers ─────────────────────────────────────────────────────────────

static __always_inline int is_ip_in_range(__u32 ip, __u32 network, __u32 prefix_len) {
    __u32 mask = ~((1U << (32 - prefix_len)) - 1);
    return (ip & mask) == (network & mask);
}

static __always_inline int is_cloudflare_ip(__u32 ip) {
    if (is_ip_in_range(ip, 0xADF53000, 20)) return 1; // 173.245.48.0/20
    return 0;
}

// ── XDP Program ─────────────────────────────────────────────────────────

SEC("xdp")
int ddos_protection(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // ── Check if destination IP is in the protected set ──
    // Use network byte order directly as the key (matches what userspace inserts)
    __u32 dst_ip_nbo = iph->daddr;
    __u8 *is_protected = bpf_map_lookup_elem(&protected_ips, &dst_ip_nbo);
    if (!is_protected)
        return XDP_PASS;  // Not a protected IP — let it through, no rate limiting

    // ── Destination is protected — apply rate limiting ──

    __u32 src_ip = __builtin_bswap32(iph->saddr);

    // Always allow Cloudflare IPs
    if (is_cloudflare_ip(src_ip))
        return XDP_PASS;

    // Composite key: rate-limit per (source → destination) pair
    // This way each VM gets its own rate limit budget per source
    __u64 composite_key = ((__u64)iph->saddr << 32) | (__u64)iph->daddr;

    __u64 current_time = bpf_ktime_get_ns();
    struct rate_limit_entry *entry = bpf_map_lookup_elem(&rate_limit_map, &composite_key);

    if (entry) {
        if (current_time - entry->last_update > INACTIVE_TIMEOUT) {
            entry->last_update = current_time;
            entry->packet_count = 1;
            return XDP_PASS;
        }

        if (current_time - entry->last_update < TIME_WINDOW_NS) {
            entry->packet_count++;
            if (entry->packet_count > THRESHOLD)
                return XDP_DROP;
        } else {
            entry->last_update = current_time;
            entry->packet_count = 1;
        }
    } else {
        struct rate_limit_entry new_entry = {};
        new_entry.last_update = current_time;
        new_entry.packet_count = 1;
        bpf_map_update_elem(&rate_limit_map, &composite_key, &new_entry, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
