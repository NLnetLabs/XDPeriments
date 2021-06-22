//#include <iproute2/bpf_elf.h> /* for struct bpf_elf_map */
//#include <linux/bpf.h>        /* of bpf_helpers.h */
//#include <bpf_helpers.h>      /* for SEC */
//#include "bpf-dns.h"

//struct rcode_key {
//    uint8_t rcode;
//};

struct bpf_elf_map SEC("maps") rcodes_v4 = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(uint32_t),
    .size_value = sizeof(uint64_t),
    .max_elem = 16,
    .pinning = PIN_GLOBAL_NS
};

struct bpf_elf_map SEC("maps") response_sizes_v4 = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(uint32_t),
    .size_value = sizeof(uint64_t),
    .max_elem = 10000,
    .pinning = PIN_GLOBAL_NS
};

struct bpf_elf_map SEC("maps") rcodes_v6 = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(uint32_t),
    .size_value = sizeof(uint64_t),
    .max_elem = 16,
    .pinning = PIN_GLOBAL_NS
};

struct bpf_elf_map SEC("maps") response_sizes_v6 = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(uint32_t),
    .size_value = sizeof(uint64_t),
    .max_elem = 10000,
    .pinning = PIN_GLOBAL_NS
};

struct bpf_elf_map SEC("maps") dnames_v4 = {
    .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
    //.type = BPF_MAP_TYPE_PERCPU_HASH,
    .size_key = 255, //TODO make this constant/configurable and consistent with tc_stats.c
    .size_value = sizeof(uint64_t),
    .max_elem = 1 * 1 * 1000,
    .pinning = PIN_GLOBAL_NS
};
struct bpf_elf_map SEC("maps") dnames_v6 = {
    .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
    //.type = BPF_MAP_TYPE_PERCPU_HASH,
    .size_key = 255, //TODO make this constant/configurable and consistent with tc_stats.c
    .size_value = sizeof(uint64_t),
    .max_elem = 1 * 1 * 1000,
    .pinning = PIN_GLOBAL_NS
};

// before we add dnames to our PER_CPU hashmap, we track them in a bloom filter
// to prevent single-timers to be wasting space in our hashmap.
// Do we care about possible race conditions in the bloom filter? It might
// introduce false negatives?  
// What if we split up the bloom filter into array elements, i.e. set max_elem
// to 'm' ( https://en.wikipedia.org/wiki/Bloom_filter ) ? Would that eliminate
// race conditions in a MAP_TYPE_ARRAY?
//
// error of 0.01
// n of 100_000
// gives 
//  m = - (n * log(e)) / (log(2)^2)
//      ==~ 958_506 ==~ 1M

struct bpf_elf_map SEC("maps") dnames_bloom = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(uint32_t),
    .size_value = 1,
    .max_elem = 1 << 30,
    .pinning = PIN_GLOBAL_NS
};

struct dname {
    char full[255];
    char tld[10];
    uint8_t len;
};

struct bpf_elf_map SEC("maps") tlds = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .size_key = sizeof(char[9]), //TODO make this constant/configurable and consistent with tc_stats.c
    .size_value = sizeof(uint64_t),
    .max_elem = 1 * 1 * 1000,
    .pinning = PIN_GLOBAL_NS
};
