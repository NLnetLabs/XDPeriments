#include <linux/ipv6.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>    /* for bpf_get_prandom_u32() */
#include "bpf-dns.h"


/* Compile-time configuration options */

#define LOG_MATCH 10    // Log every n'th message. 0 to disable logging,
                        // 1 to log everything

/* End of configuration options */

#define NAMELEN 64+64+4 +4 // 4 for padding?

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

struct key_type {
    uint32_t prefixlen;
    char dname[NAMELEN];
};

struct bpf_map_def SEC("maps") jmp_table = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 4
};

#define HANDLE_MATCH 0
#define CHECK_CACHE 1
#define PARSE_DNAME 2

struct meta_data {
	uint16_t eth_proto; // TODO can be more efficient
	uint8_t dname_pos;
	uint8_t lbl_cnt;
	uint8_t lbl1_offset;
	uint8_t lbl2_offset;
	uint8_t lbl3_offset;
};

struct bpf_map_def SEC("maps") zonelimit_dnames = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct bpf_lpm_trie_key) + NAMELEN,
    .value_size = sizeof(uint64_t),
    .max_entries = 10,
	.map_flags = BPF_F_NO_PREALLOC
};


SEC("xdp-handle-match")
int handle_match(struct xdp_md *ctx)
{
    struct cursor     c;
    struct meta_data *md = (void *)(long)ctx->data_meta;

    cursor_init(&c, ctx);
    if ((void *)(md + 1) > c.pos)
        return XDP_ABORTED;

    struct ethhdr *eth;
    struct udphdr *udp;
    struct dnshdr *dns;

    if (md->eth_proto == ETH_P_IPV6){
        struct ipv6hdr *ipv6;

        if (!(eth = parse_ethhdr(&c)) ||
                !(ipv6 = parse_ipv6hdr(&c)) ||
                !(udp = parse_udphdr(&c)) ||
                !(dns = parse_dnshdr(&c)))
            return XDP_PASS;

        struct in6_addr tmp = ipv6->saddr;
        ipv6->saddr = ipv6->daddr;
        ipv6->daddr = tmp;

    } else if (md->eth_proto == ETH_P_IP) {
        struct iphdr *ipv4;
        if (!(eth = parse_ethhdr(&c)) ||
                !(ipv4 = parse_iphdr(&c)) ||
                !(udp = parse_udphdr(&c)) ||
                !(dns = parse_dnshdr(&c)))
            return XDP_PASS;

        uint32_t tmp = ipv4->saddr; 
        ipv4->saddr = ipv4->daddr;
        ipv4->daddr = tmp;

    } else {
        bpf_printk("Not v6 nor v4? This should never happen, returning XDP_ABORTED");
        return XDP_ABORTED;
    }

    uint32_t old_flags = dns->flags.as_value;
    dns->flags.as_bits_and_pieces.qr = 1;
    dns->flags.as_bits_and_pieces.rcode = 5; // REFUSED
    uint32_t new_flags = dns->flags.as_value;

    uint32_t tmp_l4 = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp_l4;

    uint32_t csum = ~(udp->check);
    csum = bpf_csum_diff(&old_flags, 4, &new_flags, 4, csum);
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    udp->check = ~csum;

    uint8_t swap_eth[ETH_ALEN];
    memcpy(swap_eth, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, swap_eth, ETH_ALEN);

    return XDP_TX;
}

SEC("xdp-check-cache")
int check_cache(struct xdp_md *ctx)
{
	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;

	cursor_init(&c, ctx);
	if ((void *)(md + 1) > c.pos)
		return XDP_ABORTED;

    struct key_type key = { .prefixlen = 0 };
    unsigned char *keyp = (unsigned char *)&key.dname;

    // first label (TLD)
	void *offset = c.pos + (md->lbl1_offset & 0xff);
	if (offset +1 > c.end)
		return XDP_ABORTED;

    uint8_t lbl_len = *(uint8_t*)offset + 1;
    key.prefixlen += lbl_len;

    FILL_LABEL_4(keyp, offset, lbl_len);
    FILL_LABEL_2(keyp, offset, lbl_len);
    FILL_LABEL_1(keyp, offset, lbl_len);

    /* second label (SLD) */
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
    /* third label */
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
        *value += 1;
        if (LOG_MATCH > 0 && (*value % LOG_MATCH) == 0)
            bpf_printk("match for %s value: %i", &key.dname, *value);

        bpf_tail_call(ctx, &jmp_table, HANDLE_MATCH);
        return XDP_DROP;
    }
    
    return XDP_PASS;
}


SEC("xdp-parse-dname")
int parse_dname(struct xdp_md *ctx)
{

	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;

	cursor_init(&c, ctx);
	if ((void *)(md + 1) > c.pos)
		return XDP_ABORTED;
	c.pos = c.pos + (md->dname_pos & 0x7fff);

    void *offset1, *offset2, *offset3;
    offset1 = c.pos;
    offset2 = c.pos;
    offset3 = c.pos;

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
        bpf_tail_call(ctx, &jmp_table, PARSE_DNAME);

    } else if (eth->h_proto == __bpf_htons(ETH_P_IP)) {
		if (!(ipv4 = parse_iphdr(&c))
		||  !(ipv4->protocol == IPPROTO_UDP)
	 	||  !(udp = parse_udphdr(&c))
		||  !(udp->dest == __bpf_htons(DNS_PORT))
	 	||  !(dns = parse_dnshdr(&c)))
	 		return XDP_PASS; /* Not DNS */

		md->eth_proto = ETH_P_IP;
		md->dname_pos = c.pos - (void *)eth;
        bpf_tail_call(ctx, &jmp_table, PARSE_DNAME);


    }


    return XDP_PASS;

}

char __license[] SEC("license") = "GPL";
