CC=clang
LDFLAGS=-L../libbpf/src
LIBS=-lbpf -lelf -lz

DEV=lo

CFLAGS=-O3 -Wall -Werror -I../libbpf/src -D'DEFAULT_IFACE="$(DEV)"'

XDP_PROG=xdp_dns_cookies_kern.o

all: $(XDP_PROG) xdp_dns_cookies_user xdp_rrl_vipctl

$(XDP_PROG): xdp_dns_cookies_kern.c siphash4bpf.c
	$(CC) -target bpf $(CFLAGS) -c -o $@ $<

xdp_dns_cookies_user: xdp_dns_cookies_user.c
	$(CC) -static $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

xdp_rrl_vipctl: xdp_rrl_vipctl.c
	$(CC) -static $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

clean: unmount
	rm -f $(XDP_PROG) xdp_dns_cookies_user xdp_rrl_vipctl

dump: $(XDP_PROG)
	llvm-objdump -S $(XDP_PROG)

unmount:
	sudo umount /sys/fs/bpf 2>/dev/null || true
	@rm -f sys_fs_bpf_mounted

sys_fs_bpf_mounted:
	sudo mount -t bpf none /sys/fs/bpf
	@touch sys_fs_bpf_mounted

/sys/fs/bpf/rrl_exclude_v4_prefixes: sys_fs_bpf_mounted
	sudo bpftool map create /sys/fs/bpf/rrl_exclude_v4_prefixes flags 1 \
	             name exclude_v4_prefixes type lpm_trie key 8 value 8 entries 10000

/sys/fs/bpf/rrl_exclude_v6_prefixes: sys_fs_bpf_mounted
	sudo bpftool map create /sys/fs/bpf/rrl_exclude_v6_prefixes flags 1 \
	             name exclude_v6_prefixes type lpm_trie key 12 value 8 entries 10000

vip_maps: /sys/fs/bpf/rrl_exclude_v4_prefixes /sys/fs/bpf/rrl_exclude_v6_prefixes

load: $(XDP_PROG) vip_maps
	sudo ./xdp_dns_cookies_user

unload:
	sudo ip link set dev $(DEV) xdpgeneric off

show:
	sudo ip link show dev $(DEV)
