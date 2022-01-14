#include <linux/pkt_cls.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <iproute2/bpf_elf.h> /* for struct bpf_elf_map */
#include <string.h>
#include "bpf-dns.h"
#include "telemetry.h"


#define COPY_DNAME(skb, offset, dst, dname_len, n) {\
    if (dname_len >= n) {\
        bpf_skb_load_bytes(skb, offset, dst, n);\
        offset += n;\
        dst += n;\
        dname_len -= n;\
    }\
}

#define COPY_TLDe(skb, offset, dst, tld_len, n) \
    else if (tld_len == n) {\
        bpf_skb_load_bytes(skb, offset - tld_len + 1, dst, n - 1);\
    }\

struct dname {
    char full[255];
    char tld[10];
    uint8_t len;
};

// returns length of dname
// records the dname, length and tld offset in dname* res
static __always_inline
int parse_dname(struct dname *res, struct stats_key *stats_key, struct cursor *c, struct __sk_buff *skb)
{
    uint32_t offset = (uint32_t)(c->pos - (void *)(long)skb->data);

    res->len = 0;
    uint8_t tld_offset = 0;


    // determine total length of the dname, and the offset of the last label
    // FIXME reduced from 128 to 40 to please the verifier
    // can we raise this, or save intructions elsewhere?
    uint8_t i;
    for (i = 0; i < 40; i++) {
        if (c->pos + 1 > c->end) {
            return res->len;
        }

        uint8_t labellen;
        labellen = *(uint8_t*)c->pos;
        if (labellen == 0) {
            //bpf_printk("break in for loop because labellen == 0\n");
            c->pos += 1;
            break;
        }

        tld_offset = res->len;

        if (c->pos + labellen + 1 > c->end) {
            return res->len;
        }
        res->len += labellen + 1;
        c->pos += labellen + 1;
    }

    // copy the dname in chunks of 64/32/16 etc bytes

    void* to= res->full;
    uint32_t dname_len = res->len;

    COPY_DNAME(skb, offset, to, dname_len, 128);
    COPY_DNAME(skb, offset, to, dname_len, 64);
    COPY_DNAME(skb, offset, to, dname_len, 32);
    COPY_DNAME(skb, offset, to, dname_len, 16);
    COPY_DNAME(skb, offset, to, dname_len, 8);
    COPY_DNAME(skb, offset, to, dname_len, 4);
    COPY_DNAME(skb, offset, to, dname_len, 2);
    COPY_DNAME(skb, offset, to, dname_len, 1);


    // now copy the .tld
    int tld_len = res->len - tld_offset;
    //bpf_printk("tld_len: %i\n", tld_len); // XXX this one makes the loader go boo

    if (tld_len > 10) {
        bpf_skb_load_bytes(skb, offset - tld_len + 1, res->tld, 10);
    }
    COPY_TLDe(skb, offset, stats_key->tld, tld_len, 10)
    COPY_TLDe(skb, offset, stats_key->tld, tld_len, 9) 
    COPY_TLDe(skb, offset, stats_key->tld, tld_len, 8) 
    COPY_TLDe(skb, offset, stats_key->tld, tld_len, 7) 
    COPY_TLDe(skb, offset, stats_key->tld, tld_len, 6) 
    COPY_TLDe(skb, offset, stats_key->tld, tld_len, 5) 
    COPY_TLDe(skb, offset, stats_key->tld, tld_len, 4) 
    COPY_TLDe(skb, offset, stats_key->tld, tld_len, 3) 
    
    
    return res->len;
}
__always_inline 
int update_stats(
        struct __sk_buff* skb,
        struct cursor* c,
        uint8_t af, // 0 == IPv4, 1 == IPv6
		struct udphdr *udp,
		struct dnshdr *dns
        )
{

    struct stats_key sk = { 0 };
    struct dname dname = {0};
    parse_dname(&dname, &sk, c, skb);

    struct dns_qrr *qrr;
    if (!(qrr = parse_dns_qrr(c)))
        return TC_ACT_OK;

    sk.af = af;
    sk.opcode = dns->flags.as_bits_and_pieces.opcode;
    sk.rcode = dns->flags.as_bits_and_pieces.rcode;
    sk.qtype = __bpf_ntohs(qrr->qtype);
    sk.msgsize = __bpf_ntohs(udp->len);

    /*
     
    // debug output
    bpf_printk("update_stats for af=%i opcode=%i rcode=%i",
        sk.af,
        sk.opcode,
        sk.rcode
    );
    bpf_printk(" qtype=%i\n", sk.qtype);

    */

    uint64_t *cnt;
    uint64_t one = 1;
    cnt = bpf_map_lookup_elem(&stats, &sk);
    if (cnt) {
        *cnt += 1;
        //bpf_printk("cnt now %i\n", *cnt);
    } else {
        bpf_map_update_elem(&stats, &sk, &one, BPF_ANY);
    }
    return 1;
}

SEC("telemetry-egress")
int telemetry_egress(struct __sk_buff *skb)
{

	struct cursor     c;
	uint16_t          eth_proto;
	struct ethhdr    *eth;
	struct ipv6hdr   *ipv6;
	struct iphdr     *ipv4;
	struct udphdr    *udp;
	struct dnshdr    *dns;

	cursor_init_skb(&c, skb);
	if (!(eth = parse_eth(&c, &eth_proto)))
		return TC_ACT_OK;

	if (eth_proto == __bpf_htons(ETH_P_IPV6)) {
		if (!(ipv6 = parse_ipv6hdr(&c))
		||  !(ipv6->nexthdr == IPPROTO_UDP)
	 	||  !(udp = parse_udphdr(&c))
		||  !(udp->source == __bpf_htons(DNS_PORT))
	 	||  !(dns = parse_dnshdr(&c))
        )
	 		return TC_ACT_OK; /* Not DNS */

		//bpf_printk("IPv6 DNS response\n");
		update_stats(skb, &c, 1, udp, dns);

	} else if (eth_proto == __bpf_htons(ETH_P_IP)) {
        if (!(ipv4 = parse_iphdr(&c))
        ||  !(ipv4->protocol == IPPROTO_UDP)
        ||  !(udp = parse_udphdr(&c))
        ||  !(udp->source == __bpf_htons(DNS_PORT))
        ||  !(dns = parse_dnshdr(&c))
        )
            return TC_ACT_OK; /* Not DNS */

		//bpf_printk("IPv4 DNS response\n");
		update_stats(skb, &c, 0, udp, dns);
	}
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
