#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

#define THRESHOLD 350 // Max packets per second
#define TIME_WINDOW_NS 1000000000 // 1 second in nanoseconds

struct rate_limit_entry {
    __u64 last_update; // Timestamp of the last update
    __u32 packet_count; // Packet count within the time window
};

// Hash map to track rate limits for each source IP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
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
    // 173.245.48.0/20
    if (is_ip_in_range(ip, 0xADF53000, 20)) return 1;
    // 103.21.244.0/22
    if (is_ip_in_range(ip, 0x6715F400, 22)) return 1;
    // 103.22.200.0/22
    if (is_ip_in_range(ip, 0x6716C800, 22)) return 1;
    // 103.31.4.0/22
    if (is_ip_in_range(ip, 0x671F0400, 22)) return 1;
    // 141.101.64.0/18
    if (is_ip_in_range(ip, 0x8D654000, 18)) return 1;
    // 108.162.192.0/18
    if (is_ip_in_range(ip, 0x6CA2C000, 18)) return 1;
    // 190.93.240.0/20
    if (is_ip_in_range(ip, 0xBE5DF000, 20)) return 1;
    // 188.114.96.0/20
    if (is_ip_in_range(ip, 0xBC726000, 20)) return 1;
    // 197.234.240.0/22
    if (is_ip_in_range(ip, 0xC5EAF000, 22)) return 1;
    // 198.41.128.0/17
    if (is_ip_in_range(ip, 0xC6298000, 17)) return 1;
    // 162.158.0.0/15
    if (is_ip_in_range(ip, 0xA29E0000, 15)) return 1;
    // 104.16.0.0/13
    if (is_ip_in_range(ip, 0x68100000, 13)) return 1;
    // 104.24.0.0/14
    if (is_ip_in_range(ip, 0x68180000, 14)) return 1;
    // 172.64.0.0/13
    if (is_ip_in_range(ip, 0xAC400000, 13)) return 1;
    // 131.0.72.0/22
    if (is_ip_in_range(ip, 0x83004800, 22)) return 1;
    
    return 0; // Not a Cloudflare IP
}

SEC("xdp") 
int ddos_protection(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    // Check if packet is large enough to contain Ethernet header
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Check for IP packets
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header
    struct iphdr *iph = (void *)(eth + 1);
    // Check if ethernet frame is large enough to contain IP header
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
        
    // Convert source IP from network to host byte order
    __u32 src_ip = __builtin_bswap32(iph->saddr);
    
    // Check if this is a Cloudflare IP - if so, always allow
    if (is_cloudflare_ip(src_ip)) {
        return XDP_PASS; // Always allow Cloudflare traffic
    }
    
    // Continue with normal rate limiting for non-Cloudflare IPs
    // Lookup rate limit entry for this IP
    struct rate_limit_entry *entry = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    
    // Get current time in nanoseconds
    __u64 current_time = bpf_ktime_get_ns();
    
    if (entry) {
        // Check if we're in the same time window
        if (current_time - entry->last_update < TIME_WINDOW_NS) {
            entry->packet_count++;
            if (entry->packet_count > THRESHOLD) {
                return XDP_DROP; // Drop packet if rate exceeds threshold
            }
        } else {
            // New time window, reset counter
            entry->last_update = current_time;
            entry->packet_count = 1;
        }
    } else {
        // Initialize rate limit entry for new IP
        struct rate_limit_entry new_entry;
        // Zero out padding bytes
        __builtin_memset(&new_entry, 0, sizeof(new_entry));
        new_entry.last_update = current_time;
        new_entry.packet_count = 1;
        if (bpf_map_update_elem(&rate_limit_map, &src_ip, &new_entry, BPF_ANY) != 0) {
            return XDP_ABORTED; // Handle error if update fails
        }
    }
    
    return XDP_PASS; // Allow packet if under threshold   
}

char _license[] SEC("license") = "GPL";
