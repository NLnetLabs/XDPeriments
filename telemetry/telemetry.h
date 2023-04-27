#include "stats_key.h"

// BTF definition
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, sizeof(struct stats_key));
    __type(value, long);
    __uint(max_entries, 100000);
} stats SEC(".maps");

BPF_ANNOTATE_KV_PAIR(stats, int, struct stats_key);
