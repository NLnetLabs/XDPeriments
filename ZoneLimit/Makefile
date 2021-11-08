CC=clang
CFLAGS=-O2 -Wall -Werror -I ../libbpf/src -D'DEBUG=1'

DEV=eno1

XDP_PROG=xdp_zonelimit.o

all: $(XDP_PROG) xdp_zonelimit_ctl

$(XDP_PROG): xdp_zonelimit.c
	$(CC) -target bpf $(CFLAGS) -c -o $@ $<

xdp_zonelimit_ctl: xdp_zonelimit_ctl.c
	$(CC) -static $(CFLAGS) -o $@ $< -L../libbpf/src -lbpf -lelf -lz

clean:
	rm -f $(XDP_PROG) xdp_zonelimit_ctl sys_fs_bpf_mounted

dump: $(XDP_PROG)
	llvm-objdump -S $(XDP_PROG)

unmount:
	sudo umount /sys/fs/bpf 2>/dev/null || true
	@rm -f sys_fs_bpf_mounted

sys_fs_bpf_mounted:
	sudo mount -t bpf none /sys/fs/bpf
	@touch sys_fs_bpf_mounted

#/sys/fs/bpf/rrl_exclude_v4_prefixes: sys_fs_bpf_mounted
#	sudo bpftool map create /sys/fs/bpf/rrl_exclude_v4_prefixes flags 1 \
#	             name exclude_v4_prefixes type lpm_trie key 8 value 8 entries 10000
#
#/sys/fs/bpf/rrl_exclude_v6_prefixes: sys_fs_bpf_mounted
#	sudo bpftool map create /sys/fs/bpf/rrl_exclude_v6_prefixes flags 1 \
#	             name exclude_v6_prefixes type lpm_trie key 12 value 8 entries 10000
#
#vip_maps: /sys/fs/bpf/rrl_exclude_v4_prefixes /sys/fs/bpf/rrl_exclude_v6_prefixes

#/sys/fs/bpf/zonelimit_dnames: sys_fs_bpf_mounted
#	sudo bpftool map create /sys/fs/bpf/zonelimit_dnames flags 1 \
#		name zonelimit_dnames type hash key 64 value 8 entries 10

/sys/fs/bpf/zonelimit_dnames: sys_fs_bpf_mounted
	sudo bpftool map create /sys/fs/bpf/zonelimit_dnames flags 1 \
		name zonelimit_dnames type lpm_trie key 204 value 8 entries 10

maps: /sys/fs/bpf/zonelimit_dnames

load: $(XDP_PROG) maps
	sudo bpftool prog load $(XDP_PROG) /sys/fs/bpf/zonelimit type xdp \
		map name zonelimit_dnames \
		pinned /sys/fs/bpf/zonelimit_dnames
#		map name exclude_v4_prefixes \
#		pinned /sys/fs/bpf/rrl_exclude_v4_prefixes \
#		map name exclude_v6_prefixes \
#		pinned /sys/fs/bpf/rrl_exclude_v6_prefixes
	sudo ip --force link set dev $(DEV) xdpgeneric \
		pinned /sys/fs/bpf/zonelimit

unload:
	sudo ip link set dev $(DEV) xdpgeneric off
	sudo rm -f /sys/fs/bpf/zonelimit

show:
	sudo ip link show dev $(DEV)
