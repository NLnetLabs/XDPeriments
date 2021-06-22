CC=clang
LDFLAGS=-L../libbpf/src
LIBS=-lbpf -lelf -lz

DEV=lo

CFLAGS=-O3 -Wall -Werror -I../libbpf/src -D'DEFAULT_IFACE="$(DEV)"' -D'DEBUG=1'

XDP_PROG=xdp_dns_cookies_kern.o
TC_PROG=tc_stats.o

all: $(XDP_PROG) $(TC_PROG) xdp_dns_cookies_user xdp_rrl_vipctl print_stats

$(XDP_PROG): xdp_dns_cookies_kern.c siphash4bpf.c
	$(CC) -target bpf $(CFLAGS) -c -o $@ $<

$(TC_PROG): tc_stats.c tc_stats.h bpf-dns.h murmur3.c
	$(CC) -target bpf $(CFLAGS) -c -o $@ $<

xdp_dns_cookies_user: xdp_dns_cookies_user.c
	$(CC) -static $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

xdp_rrl_vipctl: xdp_rrl_vipctl.c
	$(CC) -static $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

print_stats: print_stats.c
	$(CC) -static $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

clean: unmount
	rm -f $(XDP_PROG) $(TC_PROG) xdp_dns_cookies_user xdp_rrl_vipctl print_stats

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

/sys/fs/bpf/stats_v4: sys_fs_bpf_mounted
	sudo bpftool map create /sys/fs/bpf/stats_v4 flags 1 \
	             name stats_v4 type lpm_trie key 8 value 40 entries 10000

/sys/fs/bpf/stats_v6: sys_fs_bpf_mounted
	sudo bpftool map create /sys/fs/bpf/stats_v6 flags 1 \
	             name stats_v6 type lpm_trie key 12 value 40 entries 10000

vip_maps: /sys/fs/bpf/rrl_exclude_v4_prefixes /sys/fs/bpf/rrl_exclude_v6_prefixes
stats_maps: /sys/fs/bpf/stats_v4 /sys/fs/bpf/stats_v6 

clsact:
	sudo /sbin/tc qdisc add dev $(DEV) clsact
	/usr/bin/touch clsact


tc_stats: $(TC_PROG)


load: clsact $(XDP_PROG) $(TC_PROG) vip_maps stats_maps
	sudo /sbin/tc filter del dev $(DEV) egress || true
	sudo /sbin/tc filter add dev $(DEV) egress bpf da obj $(TC_PROG) sec tc-stats-egress
	sudo ./xdp_dns_cookies_user

unload:
	sudo ip link set dev $(DEV) xdpgeneric off
	sudo /sbin/tc filter del dev $(DEV) egress || true
	sudo /sbin/tc qdisc del dev $(DEV) clsact || true
	rm -f clsact

show:
	sudo ip link show dev $(DEV)
	/sbin/tc filter show dev $(DEV) egress
