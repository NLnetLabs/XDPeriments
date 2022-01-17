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

// or: https://hur.st/bloomfilter/?n=&p=0.0001&m=4G&k=6
// with 2^29 x 1 uint8 we have m==4G _bits_ for the filter
// for error prob 1 in 10_000, and 6 hashes, we can track ~160M items


//TODO see blog posts, these numbers are outdated/off
//
struct bpf_elf_map SEC("maps") dnames_bloom = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(uint32_t),
    .size_value = 1,
    .max_elem = 1 << 27,
    .pinning = PIN_GLOBAL_NS
};

struct bpf_elf_map SEC("maps") dnames = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .size_key = 255, //TODO make this constant/configurable and consistent with tc_stats.c
    .size_value = sizeof(uint64_t),
    .max_elem = 1 * 1000 * 1000,
    .pinning = PIN_GLOBAL_NS
};

struct bpf_elf_map SEC("maps") diagnostics = {
	.type = BPF_MAP_TYPE_ARRAY,
	.size_key = sizeof(uint32_t),
	.size_value = sizeof(uint64_t),
	.max_elem = 5,
	.pinning = PIN_GLOBAL_NS
};
struct dname {
    char full[255];
    char tld[10];
    uint8_t len;
};

