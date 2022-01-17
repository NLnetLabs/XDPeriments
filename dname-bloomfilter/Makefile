CC=clang
LDFLAGS=-L../libbpf/src
LIBS=-lbpf -lelf -lz

DEV=eno1

CFLAGS=-O3 -Wall -Werror -I../libbpf/src -D'DEFAULT_IFACE="$(DEV)"' -D'DEBUG=1'

TC_PROG=dname_bloomfilter

all: $(TC_PROG) print_stats

$(TC_PROG): dname_bloomfilter.c bpf-dns.h murmur3.c
	$(CC) -target bpf $(CFLAGS) -c -o $@ $<

print_stats: print_stats.c
	$(CC) -static $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

clean: unmount
	rm -f $(TC_PROG) print_stats 

dump: $(TC_PROG)
	llvm-objdump -S $(TC_PROG)

unmount:
	sudo umount /sys/fs/bpf 2>/dev/null || true
	@rm -f sys_fs_bpf_mounted

sys_fs_bpf_mounted:
	sudo mount -t bpf none /sys/fs/bpf
	@touch sys_fs_bpf_mounted

clsact:
	sudo /sbin/tc qdisc add dev $(DEV) clsact
	/usr/bin/touch clsact


dname_bloomfilter: $(TC_PROG)


load: clsact $(TC_PROG)
	sudo /sbin/tc filter del dev $(DEV) egress || true
	sudo /sbin/tc filter add dev $(DEV) egress bpf da obj $(TC_PROG) sec dname-bloomfilter-egress

unload:
	sudo ip link set dev $(DEV) xdpgeneric off
	sudo /sbin/tc filter del dev $(DEV) egress || true
	sudo /sbin/tc qdisc del dev $(DEV) clsact || true
	rm -f clsact

show:
	sudo ip link show dev $(DEV)
	/sbin/tc filter show dev $(DEV) egress
