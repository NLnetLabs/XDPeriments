// used as the key in the BPF hashmap
struct stats_key {
    unsigned int af:1;
    unsigned int qr_bit:1;
    unsigned int do_bit:1;
    unsigned int ad_bit:1;
    unsigned int rrl_triggered:1;

    unsigned int no_edns:1;
    unsigned int edns_size_leq1231:1;
    unsigned int edns_size_1232:1;
    unsigned int edns_size_leq1399:1;
    unsigned int edns_size_1400:1;
    unsigned int edns_size_leq1499:1;
    unsigned int edns_size_1500:1;
    unsigned int edns_size_gt1500:1;

    uint8_t qtype;
    char tld[10];
};
