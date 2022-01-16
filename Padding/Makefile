CC=clang
LDFLAGS=-L../libbpf/src
LIBS=-lbpf -lelf -lz

DEV=lo

CFLAGS=-O3 -Wall -Werror -I../libbpf/src -D'DEFAULT_IFACE="$(DEV)"'

BPF_PROG=bpf_edns0_padding.o
XDP_PROG=xdp_edns0_padding.o

all: $(BPF_PROG) $(XDP_PROG)

$(BPF_PROG): bpf_edns0_padding.c bpf_edns0_padding.h bpf-dns.h
	$(CC) -target bpf $(CFLAGS) -c -o $@ $<

$(XDP_PROG): xdp_edns0_padding.c bpf_edns0_padding.h bpf-dns.h
	$(CC) -target bpf $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(BPF_PROG) $(XDP_PROG)

dump: $(BPF_PROG)
	llvm-objdump -S $(BPF_PROG)

clsact:
	sudo /sbin/tc qdisc add dev $(DEV) clsact
	/usr/bin/touch clsact

load: clsact $(BPF_PROG) $(XDP_PROG)
	sudo /sbin/tc filter del dev $(DEV) egress || true
	sudo /sbin/tc filter add dev $(DEV) egress bpf da obj $(BPF_PROG)
	sudo ip --force link set dev $(DEV) xdpgeneric obj $(XDP_PROG) sec xdp-edns0-padding-ingress

unload:
	sudo ip link set dev $(DEV) xdpgeneric off || true
	sudo /sbin/tc filter del dev $(DEV) egress || true
	sudo /sbin/tc qdisc del dev $(DEV) clsact || true
	rm -f clsact

show:
	sudo ip link show dev $(DEV)
	/sbin/tc filter show dev $(DEV) egress

debug:
	sudo cat /sys/kernel/debug/tracing/trace_pipe
