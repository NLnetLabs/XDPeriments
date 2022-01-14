// used as the key in the BPF hashmap
struct stats_key {
    uint8_t af;
    uint8_t opcode;
    uint8_t rcode;
    uint8_t qtype;
    uint16_t msgsize;
    char tld[10];
};

struct bpf_elf_map SEC("maps") stats = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(struct stats_key),
    .size_value = sizeof(uint64_t),
    .max_elem = 2*16*8*30*1500, // af * rcode * opcode * qtype * msgsize
    .pinning = PIN_GLOBAL_NS,
};
