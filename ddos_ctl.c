/*
 * ddos_ctl - Manage protected IPs for the XDP DDoS protection program
 *
 * Usage:
 *   ddos_ctl add <IP> [<IP> ...]       Add IPs to protection
 *   ddos_ctl del <IP> [<IP> ...]       Remove IPs from protection
 *   ddos_ctl list                      List all protected IPs
 *   ddos_ctl flush                     Remove all protected IPs
 *
 * The BPF map is accessed via its pinned path. The XDP program does NOT
 * need to be restarted — changes take effect immediately.
 *
 * Compile: gcc -O2 -o ddos_ctl ddos_ctl.c -lbpf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/*
 * Default pinned map path.  When you load the XDP object with libbpf and
 * set a pin_root (e.g. /sys/fs/bpf), the map named "protected_ips" will
 * appear at:  <pin_root>/protected_ips
 *
 * Adjust this if your loader uses a different pin root.
 */
#define DEFAULT_MAP_PIN "/sys/fs/bpf/protected_ips"

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s add  <IP> [<IP> ...]   Add IPs to protection\n"
        "  %s del  <IP> [<IP> ...]   Remove IPs from protection\n"
        "  %s list                   List all currently protected IPs\n"
        "  %s flush                  Remove all protected IPs\n"
        "\n"
        "Environment:\n"
        "  DDOS_MAP_PIN   Override pinned map path (default: %s)\n",
        prog, prog, prog, prog, DEFAULT_MAP_PIN);
}

static const char *get_map_pin(void) {
    const char *env = getenv("DDOS_MAP_PIN");
    return env ? env : DEFAULT_MAP_PIN;
}

static int open_map(void) {
    const char *path = get_map_pin();
    int fd = bpf_obj_get(path);
    if (fd < 0) {
        fprintf(stderr, "Error: cannot open pinned map at %s: %s\n"
                        "  Make sure the XDP program is loaded and the map is pinned.\n",
                path, strerror(errno));
    }
    return fd;
}

/* Parse a dotted-quad IPv4 string into network byte order __u32 */
static int parse_ip(const char *str, __u32 *out) {
    struct in_addr addr;
    if (inet_pton(AF_INET, str, &addr) != 1) {
        fprintf(stderr, "Error: invalid IPv4 address '%s'\n", str);
        return -1;
    }
    *out = addr.s_addr;  /* already in network byte order */
    return 0;
}

static int cmd_add(int map_fd, int argc, char **argv) {
    if (argc < 1) {
        fprintf(stderr, "Error: 'add' requires at least one IP address\n");
        return 1;
    }

    int errors = 0;
    for (int i = 0; i < argc; i++) {
        __u32 ip;
        if (parse_ip(argv[i], &ip) < 0) {
            errors++;
            continue;
        }

        __u8 val = 1;
        if (bpf_map_update_elem(map_fd, &ip, &val, BPF_ANY) != 0) {
            fprintf(stderr, "Error: failed to add %s: %s\n", argv[i], strerror(errno));
            errors++;
        } else {
            printf("Added: %s\n", argv[i]);
        }
    }
    return errors ? 1 : 0;
}

static int cmd_del(int map_fd, int argc, char **argv) {
    if (argc < 1) {
        fprintf(stderr, "Error: 'del' requires at least one IP address\n");
        return 1;
    }

    int errors = 0;
    for (int i = 0; i < argc; i++) {
        __u32 ip;
        if (parse_ip(argv[i], &ip) < 0) {
            errors++;
            continue;
        }

        if (bpf_map_delete_elem(map_fd, &ip) != 0) {
            if (errno == ENOENT)
                fprintf(stderr, "Warning: %s was not in the protected list\n", argv[i]);
            else {
                fprintf(stderr, "Error: failed to remove %s: %s\n", argv[i], strerror(errno));
                errors++;
            }
        } else {
            printf("Removed: %s\n", argv[i]);
        }
    }
    return errors ? 1 : 0;
}

static int cmd_list(int map_fd) {
    __u32 key, next_key;
    char ip_str[INET_ADDRSTRLEN];
    int count = 0;

    printf("Protected IPs:\n");
    printf("──────────────────\n");

    /* Iterate all keys in the map */
    memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(map_fd, count == 0 ? NULL : &key, &next_key) == 0) {
        struct in_addr addr = { .s_addr = next_key };
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        printf("  %s\n", ip_str);
        key = next_key;
        count++;
    }

    if (count == 0)
        printf("  (none)\n");
    else
        printf("──────────────────\n");

    printf("Total: %d\n", count);
    return 0;
}

static int cmd_flush(int map_fd) {
    __u32 key, next_key;
    int count = 0;

    while (bpf_map_get_next_key(map_fd, NULL, &next_key) == 0) {
        bpf_map_delete_elem(map_fd, &next_key);
        count++;
    }

    printf("Flushed %d IP(s) from protected list\n", count);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        usage(argv[0]);
        return 0;
    }

    int map_fd = open_map();
    if (map_fd < 0)
        return 1;

    int ret;
    if (strcmp(cmd, "add") == 0)
        ret = cmd_add(map_fd, argc - 2, argv + 2);
    else if (strcmp(cmd, "del") == 0)
        ret = cmd_del(map_fd, argc - 2, argv + 2);
    else if (strcmp(cmd, "list") == 0)
        ret = cmd_list(map_fd);
    else if (strcmp(cmd, "flush") == 0)
        ret = cmd_flush(map_fd);
    else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage(argv[0]);
        ret = 1;
    }

    close(map_fd);
    return ret;
}
