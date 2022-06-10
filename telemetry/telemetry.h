// used as the key in the BPF hashmap
struct stats_key {
    uint8_t af;
    uint8_t qtype;
    uint8_t qr_bit;
    uint8_t do_bit;
    uint8_t ad_bit;
    uint8_t rrl_triggered;

    uint8_t no_edns;
    uint8_t edns_size_leq1231;
    uint8_t edns_size_1232;
    uint8_t edns_size_leq1399;
    uint8_t edns_size_1400;
    uint8_t edns_size_leq1499;
    uint8_t edns_size_1500;
    uint8_t edns_size_gt1500;

    char tld[10];
};

// BTF definition
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, sizeof(struct stats_key));
    __type(value, long);
    __uint(max_entries, 100000);
} stats SEC(".maps");

BPF_ANNOTATE_KV_PAIR(stats, int, struct stats_key);
