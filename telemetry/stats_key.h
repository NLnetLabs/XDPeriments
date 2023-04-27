// used as the key in the BPF hashmap
struct stats_key {
    uint8_t af:1;
    uint8_t qr_bit:1;
    uint8_t do_bit:1;
    uint8_t ad_bit:1;
    uint8_t rrl_triggered:1;

    uint8_t no_edns:1;
    uint8_t edns_size_leq1231:1;
    uint8_t edns_size_1232:1;
    uint8_t edns_size_leq1399:1;
    uint8_t edns_size_1400:1;
    uint8_t edns_size_leq1499:1;
    uint8_t edns_size_1500:1;
    uint8_t edns_size_gt1500:1;

    uint8_t qtype;
    char tld[10];
};
