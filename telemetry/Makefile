CC=clang
LDFLAGS=-L../libbpf/src
LIBS=-lbpf -lelf -lz

DEV=eno1

# we need -g for the BTF definition of maps
CFLAGS=-g -O3 -Wall -Werror -I../libbpf/src -D'DEFAULT_IFACE="$(DEV)"' -D'DEBUG=1'

XDP_PROG=telemetry.o

all: $(XDP_PROG) print_telemetry

$(XDP_PROG): telemetry.c telemetry.h bpf-dns.h
	$(CC) -target bpf $(CFLAGS) -c -o $@ $<

print_telemetry: print_telemetry.c
	$(CC) -static $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

print_influxdb: print_influxdb.c
	$(CC) -static $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

clean: unmount
	rm -f $(XDP_PROG) print_telemetry

dump: $(XDP_PROG)
	llvm-objdump -S $(XDP_PROG)

unmount:
	sudo umount /sys/fs/bpf 2>/dev/null || true
	@rm -f sys_fs_bpf_mounted

sys_fs_bpf_mounted:
	sudo mount -t bpf none /sys/fs/bpf
	@touch sys_fs_bpf_mounted

stats_map: 
	sudo bpftool map create /sys/fs/bpf/stats flags 1 \
		name stats type hash key 16 value 8 entries 100000

load: $(XDP_PROG) stats_map
	#sudo ip --force link set dev $(DEV) xdpgeneric obj $(XDP_PROG) sec xdp-telemetry-ingress
	sudo bpftool prog load $(XDP_PROG) /sys/fs/bpf/telemetry_ingress type xdp \
		map name stats \
		pinned /sys/fs/bpf/stats
	sudo ip --force link set dev $(DEV) xdpgeneric \
		pinned /sys/fs/bpf/telemetry_ingress

unload:
	sudo ip link set dev $(DEV) xdpgeneric off
	sudo rm -f /sys/fs/bpf/telemetry_ingress
	sudo rm -f /sys/fs/bpf/stats

show:
	sudo ip link show dev $(DEV)
