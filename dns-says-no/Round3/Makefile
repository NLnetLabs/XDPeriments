CC=clang
CFLAGS=-O -Wall -Werror -I../../libbpf/src

DEV=lo

XDP_PROG=xdp_dns_says_no_kern_v3.o

all: $(XDP_PROG)

$(XDP_PROG): xdp_dns_says_no_kern_v3.c
	$(CC) -target bpf $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(XDP_PROG)

dump: $(XDP_PROG)
	llvm-objdump -S $(XDP_PROG)

load: $(XDP_PROG)
	sudo ip --force link set dev $(DEV) xdpgeneric obj $(XDP_PROG) sec xdp-dns-says-no-v3

unload:
	sudo ip link set dev $(DEV) xdpgeneric off

show:
	sudo ip link show dev $(DEV)
