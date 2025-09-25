#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

#define THRESHOLD 350 // Max packets per second
#define TIME_WINDOW_NS 1000000000ULL // 1 second
#define INACTIVE_TIMEOUT (300ULL * TIME_WINDOW_NS) // 5 minutes

struct rate_limit_entry {
    __u64 last_update; // Timestamp of the last update
    __u32 packet_count; // Packet count within the time window
};

// Use LRU map so old entries get evicted automatically
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32); // Source IP
    __type(value, struct rate_limit_entry);
} rate_limit_map SEC(".maps");

// Helper function to check if IP is in a CIDR range
static __always_inline int is_ip_in_range(__u32 ip, __u32 network, __u32 prefix_len) {
    __u32 mask = ~((1U << (32 - prefix_len)) - 1);
    return (ip & mask) == (network & mask);
}

// Function to check if IP is in Cloudflare ranges
static __always_inline int is_cloudflare_ip(__u32 ip) {
    // Cloudflare IPv4 ranges (in host byte order)
    if (is_ip_in_range(ip, 0xADF53000, 20)) return 1; // 173.245.48.0/20
    if (is_ip_in_range(ip, 0x6715F400, 22)) return 1; // 103.21.244.0/22
    if (is_ip_in_range(ip, 0x6716C800, 22)) return 1; // 103.22.200.0/22
    if (is_ip_in_range(ip, 0x671F0400, 22)) return 1; // 103.31.4.0/22
    if (is_ip_in_range(ip, 0x8D654000, 18)) return 1; // 141.101.64.0/18
    if (is_ip_in_range(ip, 0x6CA2C000, 18)) return 1; // 108.162.192.0/18
    if (is_ip_in_range(ip, 0xBE5DF000, 20)) return 1; // 190.93.240.0/20
    if (is_ip_in_range(ip, 0xBC726000, 20)) return 1; // 188.114.96.0/20
    if (is_ip_in_range(ip, 0xC5EAF000, 22)) return 1; // 197.234.240.0/22
    if (is_ip_in_range(ip, 0xC6298000, 17)) return 1; // 198.41.128.0/17
    if (is_ip_in_range(ip, 0xA29E0000, 15)) return 1; // 162.158.0.0/15
    if (is_ip_in_range(ip, 0x68100000, 13)) return 1; // 104.16.0.0/13
    if (is_ip_in_range(ip, 0x68180000, 14)) return 1; // 104.24.0.0/14
    if (is_ip_in_range(ip, 0xAC400000, 13)) return 1; // 172.64.0.0/13
    if (is_ip_in_range(ip, 0x83004800, 22)) return 1; // 131.0.72.0/22
    return 0;
}

SEC("xdp")
int ddos_protection(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only handle IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = __builtin_bswap32(iph->saddr);

    // Always allow Cloudflare IPs
    if (is_cloudflare_ip(src_ip))
        return XDP_PASS;

    __u64 current_time = bpf_ktime_get_ns();
    struct rate_limit_entry *entry = bpf_map_lookup_elem(&rate_limit_map, &src_ip);

    if (entry) {
        // Check inactivity timeout
        if (current_time - entry->last_update > INACTIVE_TIMEOUT) {
            entry->last_update = current_time;
            entry->packet_count = 1;
            return XDP_PASS;
        }

        // Same window
        if (current_time - entry->last_update < TIME_WINDOW_NS) {
            entry->packet_count++;
            if (entry->packet_count > THRESHOLD)
                return XDP_DROP;
        } else {
            // New window
            entry->last_update = current_time;
            entry->packet_count = 1;
        }
    } else {
        struct rate_limit_entry new_entry = {};
        new_entry.last_update = current_time;
        new_entry.packet_count = 1;
        bpf_map_update_elem(&rate_limit_map, &src_ip, &new_entry, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
