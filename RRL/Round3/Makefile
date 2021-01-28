CC=clang
CFLAGS=-O2 -Wall -Werror -I ../../libbpf/src

DEV=eth0

XDP_PROG=xdp_rrl.o

all: $(XDP_PROG) xdp_rrl_vipctl

$(XDP_PROG): xdp_rrl.c
	$(CC) -target bpf $(CFLAGS) -c -o $@ $<

xdp_rrl_vipctl: xdp_rrl_vipctl.c
	$(CC) -static $(CFLAGS) -o $@ $< -L../../libbpf/src -lbpf -lelf -lz

clean:
	rm -f $(XDP_PROG) xdp_rrl_vipctl sys_fs_bpf_mounted

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
	sudo bpftool prog load $(XDP_PROG) /sys/fs/bpf/rrl type xdp \
		map name exclude_v4_prefixes \
		pinned /sys/fs/bpf/rrl_exclude_v4_prefixes \
		map name exclude_v6_prefixes \
		pinned /sys/fs/bpf/rrl_exclude_v6_prefixes
	sudo ip --force link set dev $(DEV) xdpgeneric \
		pinned /sys/fs/bpf/rrl

unload:
	sudo ip link set dev $(DEV) xdpgeneric off
	sudo rm -f /sys/fs/bpf/rrl

show:
	sudo ip link show dev $(DEV)
