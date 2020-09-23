#!/bin/sh

# Cleanup the previous maps
sudo umount /sys/fs/bpf || true

# Mount the bpf filesystem for pinned maps
sudo mount -t bpf none /sys/fs/bpf

## create pinned map for:
#
# struct bpf_map_def SEC("maps") exclude_v4_prefixes = {
#	.type = BPF_MAP_TYPE_LPM_TRIE,
#	.key_size = sizeof(struct bpf_lpm_trie_key) + sizeof(uint32_t),
#	.value_size = sizeof(uint64_t),
#	.max_entries = 1000000
# };
#
## sizeof(struct bpf_lpm_trie_key) + sizeof(uint32_t) = 4 + 4 = 8
## sizeof(uint64_t) = 8

sudo bpftool map create /sys/fs/bpf/rrl_exclude_v4_prefixes flags 1 \
	name exclude_v4_prefixes type lpm_trie key 8 value 8 entries 10000

# add 185.49.142.0/24
sudo bpftool map update pinned /sys/fs/bpf/rrl_exclude_v4_prefixes \
	key 24 0 0 0 185 49 142 0 value 0 0 0 0 0 0 0 0

# add 80.114.156.98
sudo bpftool map update pinned /sys/fs/bpf/rrl_exclude_v4_prefixes \
	key 24 0 0 0 80 114 156 98 value 0 0 0 0 0 0 0 0

## create pinned map for:
#
# struct bpf_map_def SEC("maps") exclude_v6_prefixes = {
#	.type = BPF_MAP_TYPE_LPM_TRIE,
#	.key_size = sizeof(struct bpf_lpm_trie_key) + 8, // first 64 bits
#	.value_size = sizeof(uint64_t),
#	.max_entries = 1000000
# };
#
## sizeof(struct bpf_lpm_trie_key) + 8 = 4 + 8 = 12
## sizeof(uint64_t) = 8

sudo bpftool map create /sys/fs/bpf/rrl_exclude_v6_prefixes flags 1 \
	name exclude_v6_prefixes type lpm_trie key 12 value 8 entries 10000

# add 2a04:b900::/22
sudo bpftool map update pinned /sys/fs/bpf/rrl_exclude_v6_prefixes \
	key hex 16 00 00 00 2a 04 b9 00 00 00 00 00 value 0 0 0 0 0 0 0 0

