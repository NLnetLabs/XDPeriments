#include <linux/bpf.h>
#include <bpf_helpers.h>    /* for bpf_get_prandom_u32() */
#include "bpf-dns.h"

#define FILL_LABEL_64(dst, src, lbl_len) {\
    if (lbl_len >= 64 && offset + 64 <= c.end) {\
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        lbl_len -= 64; \
    } \
}
#define FILL_LABEL_32(dst, src, lbl_len) {\
    if (lbl_len >= 32 && offset + 32 <= c.end) {\
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        lbl_len -= 32; \
    } \
}

#define FILL_LABEL_16(dst, src, lbl_len) {\
    if (lbl_len >= 16 && offset + 16 <= c.end) {\
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        lbl_len -= 16; \
    } \
}


#define FILL_LABEL_8(dst, src, lbl_len) {\
    if (lbl_len >= 8 && offset + 8 <= c.end) {\
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        lbl_len -= 8; \
    } \
}
#define FILL_LABEL_4(dst, src, lbl_len) {\
    if (lbl_len >= 4 && offset + 4 <= c.end) {\
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        lbl_len -= 4; \
    } \
}

#define FILL_LABEL_2(dst, src, lbl_len) {\
    if (lbl_len >= 2 && offset + 2 <= c.end) {\
        *dst++ = *(char*)src++; *dst++ = *(char*)src++; \
        lbl_len -= 2; \
    } \
}
#define FILL_LABEL_1(dst, src, lbl_len) {\
    if (lbl_len >= 1 && offset + 1 <= c.end) {\
        *dst++ = *(char*)src++; \
        lbl_len -= 1; \
    } \
}

#define NAMELEN 64+64+4 +4 // 4 for padding?

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

#define CHECK_CACHE 0
#define PARSE_DNAME 1

struct meta_data {
	uint16_t eth_proto;
	//uint16_t ip_pos;
	uint16_t dname_pos;
	uint8_t lbl_cnt;
	uint16_t lbl1_offset;
	uint16_t lbl2_offset;
	uint16_t lbl3_offset;
	//uint16_t unused;
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

SEC("xdp-check-cache")
int check_cache(struct xdp_md *ctx)
{
	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;

	cursor_init(&c, ctx);
	if ((void *)(md + 1) > c.pos) // || c.pos + md->dname_pos > c.end)
		return XDP_ABORTED;

    struct key_type key = { .prefixlen = 0 };
    unsigned char *keyp = (unsigned char *)&key.dname;
    //__builtin_memset(keyp, 0, 200);

    // first label (TLD)
	void *offset = c.pos + (md->lbl1_offset & 0xff);
	if (offset +1 > c.end)
		return XDP_ABORTED;

    uint8_t lbl_len = *(uint8_t*)offset + 1;
    key.prefixlen += lbl_len;

    FILL_LABEL_4(keyp, offset, lbl_len);
    FILL_LABEL_2(keyp, offset, lbl_len);
    FILL_LABEL_1(keyp, offset, lbl_len);

    if (md->lbl_cnt >= 2) {
		offset = c.pos + (md->lbl2_offset & 0xff);
		if (offset + 1 > c.end)
			return XDP_ABORTED;

        lbl_len = *(uint8_t*)offset + 1;
        key.prefixlen += lbl_len;

        if (lbl_len == 64) {
            FILL_LABEL_64(keyp, offset, lbl_len);
        } else {
            FILL_LABEL_32(keyp, offset, lbl_len);
            FILL_LABEL_16(keyp, offset, lbl_len);
            FILL_LABEL_8(keyp, offset, lbl_len);
            FILL_LABEL_4(keyp, offset, lbl_len);
            FILL_LABEL_2(keyp, offset, lbl_len);
            FILL_LABEL_1(keyp, offset, lbl_len);
        }

    }
    if (md->lbl_cnt >= 3) {
		offset = c.pos + (md->lbl3_offset & 0xff);
		if (offset + 1 > c.end)
			return XDP_ABORTED;

        lbl_len = *(uint8_t*)offset + 1;
        key.prefixlen += lbl_len;

        if (lbl_len == 64) {
            FILL_LABEL_64(keyp, offset, lbl_len);
        } else {
            FILL_LABEL_32(keyp, offset, lbl_len);
            FILL_LABEL_16(keyp, offset, lbl_len);
            FILL_LABEL_8(keyp, offset, lbl_len);
            FILL_LABEL_4(keyp, offset, lbl_len);
            FILL_LABEL_2(keyp, offset, lbl_len);
            FILL_LABEL_1(keyp, offset, lbl_len);
        }

    }
	
    key.prefixlen *= 8; // from bytes to bits
    uint64_t *value;
    if ((value = bpf_map_lookup_elem(&zonelimit_dnames, &key))) {
        //bpf_printk("matched on %s with prefixlen %i, value: %i", &key.dname, key.prefixlen, *value);
        bpf_printk("matched %i", *value);
        *value += 1;
        return XDP_DROP;
    }
    
    return XDP_PASS;
}


SEC("xdp-parse-dname")
int parse_dname(struct xdp_md *ctx)//, struct __sk_buff *skb)
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

    //uint8_t in_packet_len = 0;
    uint8_t i;
    uint8_t num_lbls = 0;
    uint8_t labellen;

    for (i = 0; i < 128; i++) {
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
        //in_packet_len += labellen + 1;
        c.pos += labellen + 1;
    }
    if (c.pos + 1 > c.end) {
        return XDP_PASS;
    }

	md->lbl_cnt = (uint8_t)num_lbls;
	md->lbl1_offset = offset1 - (void*)(long)ctx->data;
	md->lbl2_offset = offset2 - (void*)(long)ctx->data;
	md->lbl3_offset = offset3 - (void*)(long)ctx->data;

    bpf_tail_call(ctx, &jmp_table, CHECK_CACHE);


	return XDP_PASS;

}

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


	if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct meta_data))) {
		bpf_printk("failed to adjust_meta, struct too large?");
		return XDP_PASS;
	}

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
        bpf_tail_call(ctx, &jmp_table, PARSE_DNAME);
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
        bpf_tail_call(ctx, &jmp_table, PARSE_DNAME);
        bpf_printk("--------------------\n\n");


    }


    return XDP_PASS;

}

char __license[] SEC("license") = "GPL";
