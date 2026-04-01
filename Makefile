IFACE ?= lo
PROG ?= xdp_ddos_protection
MAP ?= rate_limit_map
PIN_DIR ?= /sys/fs/bpf
CTL ?= ddos_ctl

.PHONY: all compile clean attach detach dump pin unpin ctl

all: detach clean compile attach pin dump ctl

compile: clean
	clang -O2 -g -target bpf -c $(PROG).c -o $(PROG).o

clean:
	rm -f $(PROG).o $(CTL)

attach:
	sudo ip link set dev $(IFACE) xdp obj $(PROG).o sec xdp

detach:
	sudo ip link set dev $(IFACE) xdp off

# Pin the protected_ips map so ddos_ctl can access it at runtime
pin:
	@sudo mkdir -p $(PIN_DIR)
	@MAP_ID=$$(sudo bpftool map show | grep 'protected_ips' | awk '{print $$1}' | tr -d ':'); \
	if [ -n "$$MAP_ID" ]; then \
		sudo bpftool map pin id $$MAP_ID $(PIN_DIR)/protected_ips 2>/dev/null || true; \
		echo "✓ protected_ips map pinned at $(PIN_DIR)/protected_ips"; \
	else \
		echo "✗ Could not find protected_ips map — is the program attached?"; \
		exit 1; \
	fi

unpin:
	sudo rm -f $(PIN_DIR)/protected_ips

# Build the CLI tool for managing protected IPs
ctl: $(CTL)

$(CTL): $(CTL).c
	gcc -O2 -Wall -o $@ $< -lbpf

iface-inspect:
	sudo ip link show $(IFACE)

dump:
	sudo bpftool map dump name $(MAP) &> /dev/null
