CC=clang
CFLAGS=-O2 -Wall -Werror -I ../../libbpf/src

DEV=eth0

XDP_PROG=xdp_rrl_VIP_list.o

all: $(XDP_PROG)

$(XDP_PROG): xdp_rrl_VIP_list.c
	$(CC) -target bpf $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(XDP_PROG)

dump: $(XDP_PROG)
	llvm-objdump -S $(XDP_PROG)

load: $(XDP_PROG)
	sudo bpftool prog load $(XDP_PROG) /sys/fs/bpf/rrl_VIP_list type xdp \
		map name exclude_v4_prefixes \
		pinned /sys/fs/bpf/rrl_exclude_v4_prefixes \
		map name exclude_v6_prefixes \
		pinned /sys/fs/bpf/rrl_exclude_v6_prefixes
	sudo ip --force link set dev $(DEV) xdpgeneric \
		pinned /sys/fs/bpf/rrl_VIP_list

unload:
	sudo ip link set dev $(DEV) xdpgeneric off
	sudo rm -f /sys/fs/bpf/rrl_VIP_list

show:
	sudo ip link show dev $(DEV)
