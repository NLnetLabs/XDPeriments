#include <linux/bpf.h>
#include <bpf_helpers.h>    /* for bpf_get_prandom_u32() */
#include "bpf-dns.h"

struct dname {
    char full[255];
    char tld[10];
    uint8_t len;
};

#define COPY_DNAME(skb, offset, dst, dname_len, n) {\
    if (dname_len >= n) {\
        bpf_skb_load_bytes(skb, offset, dst, n);\
        offset += n;\
        dst += n;\
        dname_len -= n;\
    }\
}

//#define COPY_LABEL(dst, dst_offset, lbl, lbl_offset, lbl_len, N) {\
//    if (lbl_len >= N) {\
//        if ((void*)(lbl + lbl_offset + N) > c->end) { \
//            return 0;\
//        }\
//        __builtin_memcpy(dst + dst_offset, lbl + lbl_offset, N);\
//        dst_offset += N;\
//        lbl_offset += N;\
//        lbl_len -= N;\
//    }\
//}

#define COPY_LABEL(dst, lbl, lbl_len, N) {\
    if (lbl_len >= N) {\
        if ((void*)(lbl) + N > c.end) {\
            return 0;\
        }\
        __builtin_memcpy(dst, lbl, N);\
        dst += N;\
        lbl += N;\
        lbl_len -= N;\
    }\
}


#define NAMELEN 200

struct key_type {
    uint32_t prefixlen;
    char dname[NAMELEN];
};

struct bpf_map_def SEC("maps") jmp_table = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 3
};

#define CHECK_DNAME 0

struct meta_data {
	uint16_t eth_proto;
	uint16_t ip_pos;
	uint16_t dname_pos;
	uint16_t unused;
};

struct bpf_map_def SEC("maps") zonelimit_dnames = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct bpf_lpm_trie_key) + NAMELEN,
    .value_size = sizeof(uint64_t),
    .max_entries = 10,
	.map_flags = BPF_F_NO_PREALLOC
};

//static __always_inline
//int parse_dname(struct cursor *c)//, struct __sk_buff *skb)

SEC("xdp-check-dname")
int check_dname(struct xdp_md *ctx)//, struct __sk_buff *skb)
{

	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;

	cursor_init(&c, ctx);
	if ((void *)(md + 1) > c.pos) // || c.pos + md->dname_pos > c.end)
		return XDP_ABORTED;

    //bpf_printk("jumped into CHECK_DNAME for eth %X, offset %i", md->eth_proto, md->dname_pos);
	//bpf_printk("c->end - c->start: %i", c.end - c.pos);
	//if (c.pos + md->dname_pos > c.end)
	//	return XDP_ABORTED;

	//if (md->dname_pos == 74)
	//	bpf_printk("it's 74 alright");
	c.pos = c.pos + (md->dname_pos & 0x7fff);
	//c.pos += 74;

    void *offset1, *offset2, *offset3;
    offset1 = c.pos;
    offset2 = c.pos;
    offset3 = c.pos;

    uint8_t in_packet_len = 0;
    uint8_t i;
    uint8_t num_lbls = 0;
    uint8_t labellen;

    for (i = 0; i < 5; i++) {
        if (c.pos + 1 > c.end) {
            return XDP_PASS;
        }

        labellen = *(uint8_t*)c.pos;
        if (labellen == 0)
            break;

        num_lbls += 1;
        offset3 = offset2;
        offset2 = offset1;
        offset1 = c.pos;

        //tld_offset = res->len;

        if (c.pos + labellen + 1 > c.end) {
            return XDP_PASS;
        }
        //res->len += labellen + 1;
        in_packet_len += labellen + 1;
        c.pos += labellen + 1;
    }
    if (c.pos + 1 > c.end) {
        return XDP_PASS;
    }

    struct key_type key = { .prefixlen = 0 };
    void *keyp = &key.dname;

    // first label (TLD)
    uint8_t ll_1 = *(uint8_t*)offset1 + 1;
    key.prefixlen += ll_1;

    //COPY_LABEL(keyp, offset1, ll_1, 16);
    //COPY_LABEL(keyp, offset1, ll_1, 8);
    COPY_LABEL(keyp, offset1, ll_1, 4);
    COPY_LABEL(keyp, offset1, ll_1, 2);
    COPY_LABEL(keyp, offset1, ll_1, 1);

    if (num_lbls >= 2) {
        // reset label offset for the next label
        uint8_t ll_2 = *(uint8_t*)offset2 + 1;
        key.prefixlen += ll_2;
        //COPY_LABEL(keyp, offset2, ll_2, 64);
        //COPY_LABEL(keyp, offset2, ll_2, 32);
        COPY_LABEL(keyp, offset2, ll_2, 16);
        COPY_LABEL(keyp, offset2, ll_2, 8);
        COPY_LABEL(keyp, offset2, ll_2, 4);
        COPY_LABEL(keyp, offset2, ll_2, 2);
        COPY_LABEL(keyp, offset2, ll_2, 1);
    }
    
    
    if (num_lbls >= 3) {
        // reset label offset for the next label
        uint8_t ll_3 = *(uint8_t*)offset3 + 1;
        key.prefixlen += ll_3;
        //COPY_LABEL(keyp, offset3, ll_3, 64);
        COPY_LABEL(keyp, offset3, ll_3, 32);
        COPY_LABEL(keyp, offset3, ll_3, 16);
        COPY_LABEL(keyp, offset3, ll_3, 8);
        COPY_LABEL(keyp, offset3, ll_3, 4);
        COPY_LABEL(keyp, offset3, ll_3, 2);
        COPY_LABEL(keyp, offset3, ll_3, 1);
    }
    
    

    key.prefixlen *= 8; // from bytes to bits
    uint64_t *value;
    if ((value = bpf_map_lookup_elem(&zonelimit_dnames, &key))) {
        bpf_printk("matched on %s with prefixlen %i, value: %i", &key.dname, key.prefixlen, *value);
        *value += 1;
    }

    return XDP_PASS;
}

//static __always_inline
//int check_dname(struct cursor *c)
//{
//    //struct dname dname = {0};
//    parse_dname(c);
//    return 1;
//}

SEC("xdp-zonelimit")
int xdp_zonelimit(struct xdp_md *ctx)
{
	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct ethhdr    *eth;
	struct ipv6hdr   *ipv6;
	struct iphdr     *ipv4;
	struct udphdr    *udp;
	struct dnshdr    *dns;


	if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct meta_data)))
		return XDP_PASS;

	cursor_init(&c, ctx);
	md = (void *)(long)ctx->data_meta;
	if ((void *)(md + 1) > c.pos)
		return XDP_PASS;

	md->dname_pos = 0;
	if (!(eth = parse_ethhdr(&c)))
		return XDP_PASS;

	if (eth->h_proto == __bpf_htons(ETH_P_IPV6)) {
		if (!(ipv6 = parse_ipv6hdr(&c))
		||  !(ipv6->nexthdr == IPPROTO_UDP)
	 	||  !(udp = parse_udphdr(&c))
		||  !(udp->dest == __bpf_htons(DNS_PORT))
	 	||  !(dns = parse_dnshdr(&c)))
	 		return XDP_PASS; /* Not DNS */

		md->eth_proto = ETH_P_IPV6;
		md->dname_pos = c.pos - (void *)eth;
        bpf_printk("got v6 DNS: %x", (ETH_P_IPV6));
        //check_dname(&c);
        bpf_tail_call(ctx, &jmp_table, CHECK_DNAME);
        bpf_printk("--------------------\n\n");

    } else if (eth->h_proto == __bpf_htons(ETH_P_IP)) {
		if (!(ipv4 = parse_iphdr(&c))
		||  !(ipv4->protocol == IPPROTO_UDP)
	 	||  !(udp = parse_udphdr(&c))
		||  !(udp->dest == __bpf_htons(DNS_PORT))
	 	||  !(dns = parse_dnshdr(&c)))
	 		return XDP_PASS; /* Not DNS */

        bpf_printk("got v4 DNS: %x", (ETH_P_IP));
		md->eth_proto = ETH_P_IP;
		md->dname_pos = c.pos - (void *)eth;
        // XXX enabling on both v6 and v4 hits verifier limits if we track the
        // last 3 labels. For the last 2 labels (so domain.tld), it works..
        //check_dname(&c);
        bpf_tail_call(ctx, &jmp_table, CHECK_DNAME);
        bpf_printk("--------------------\n\n");


    }


    return XDP_PASS;

}

char __license[] SEC("license") = "GPL";
