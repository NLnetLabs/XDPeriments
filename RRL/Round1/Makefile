CC=clang
CFLAGS=-O -Wall -Werror -I ../../libbpf/src

DEV=lo

XDP_PROG=xdp_rrl_per_ip.o

all: $(XDP_PROG)

$(XDP_PROG): xdp_rrl_per_ip.c
	$(CC) -target bpf $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(XDP_PROG)

dump: $(XDP_PROG)
	llvm-objdump -S $(XDP_PROG)

load: $(XDP_PROG)
	sudo ip --force link set dev $(DEV) xdpgeneric obj $(XDP_PROG) sec xdp-rrl-per-ip

unload:
	sudo ip link set dev $(DEV) xdpgeneric off

show:
	sudo ip link show dev $(DEV)
