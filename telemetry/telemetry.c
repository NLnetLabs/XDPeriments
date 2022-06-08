#include <linux/pkt_cls.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <iproute2/bpf_elf.h> /* for struct bpf_elf_map */
#include <string.h>
#include "bpf-dns.h"
#include "telemetry.h"

#define memcpy __builtin_memcpy

#define COPY_DNAME(data, dst, dname_len, n) {\
    if (dname_len >= n) {\
        if (data + n > c->end) {\
            return XDP_PASS;\
        }\
        memcpy(dst, data, n);\
        data += n;\
        dst += n;\
        dname_len -= n;\
    }\
}

#define COPY_TLDe(data, offset, dst, tld_len, n) \
    else if (tld_len == n) {\
        memcpy(data + offset - tld_len + 1, dst, n - 1);\
    }\

struct dname {
    char full[255];
    char tld[10];
    uint8_t len;
};

// returns length of dname
// records the dname, length and tld offset in dname* res
static __always_inline
int parse_dname(struct dname *res, struct stats_key *stats_key, struct cursor *c) //, struct __sk_buff *skb)
{
    //uint32_t offset = (uint32_t)(c->pos - (void *)(long)skb->data);
    void *cstart = c->pos; //(uint32_t)(c->pos - (void *)(long)c;


    res->len = 0;
    //uint8_t tld_offset = 0;


    // determine total length of the dname, and the offset of the last label
    // FIXME reduced from 128 to 40 to please the verifier
    // can we raise this, or save intructions elsewhere?
    uint8_t i;
    for (i = 0; i < 10; i++) {
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

        //tld_offset = res->len;

        if (c->pos + labellen + 1 > c->end) {
            return res->len;
        }
        res->len += labellen + 1;
        c->pos += labellen + 1;
    }

    // copy the dname in chunks of 64/32/16 etc bytes

    void* to= res->full;
    uint32_t dname_len = res->len;

    //COPY_DNAME(cstart, to, dname_len, 128);
    COPY_DNAME(cstart, to, dname_len, 64);
    COPY_DNAME(cstart, to, dname_len, 32);
    COPY_DNAME(cstart, to, dname_len, 16);
    COPY_DNAME(cstart, to, dname_len, 8);
    COPY_DNAME(cstart, to, dname_len, 4);
    COPY_DNAME(cstart, to, dname_len, 2);
    COPY_DNAME(cstart, to, dname_len, 1);

    /*

       // FIXME fix offset here

    // now copy the .tld
    int tld_len = res->len - tld_offset;
    //bpf_printk("tld_len: %i\n", tld_len); // XXX this one makes the loader go boo

    if (tld_len > 10) {
        //bpf_skb_load_bytes(skb, offset - tld_len + 1, res->tld, 10);
        memcpy(cstart + offset - tld_len + 1, res->tld, 10);
    }
    COPY_TLDe(cstart, offset, stats_key->tld, tld_len, 10)
    COPY_TLDe(cstart, offset, stats_key->tld, tld_len, 9) 
    COPY_TLDe(cstart, offset, stats_key->tld, tld_len, 8) 
    COPY_TLDe(cstart, offset, stats_key->tld, tld_len, 7) 
    COPY_TLDe(cstart, offset, stats_key->tld, tld_len, 6) 
    COPY_TLDe(cstart, offset, stats_key->tld, tld_len, 5) 
    COPY_TLDe(cstart, offset, stats_key->tld, tld_len, 4) 
    COPY_TLDe(cstart, offset, stats_key->tld, tld_len, 3) 
    
    */
    
    bpf_printk("tld_len: %i\n", res->len);
    return res->len;
}
__always_inline 
int update_stats(
        //struct __sk_buff* skb,
        struct cursor* c,
        uint8_t af, // 0 == IPv4, 1 == IPv6
		struct udphdr *udp,
		struct dnshdr *dns
        )
{

    struct stats_key sk = { 0 };
    struct dname dname = {0};

    // info from DNS header
    sk.af = af;
    sk.qr_bit = dns->flags.as_bits_and_pieces.qr;
    sk.ad_bit = dns->flags.as_bits_and_pieces.ad;

    parse_dname(&dname, &sk, c);

    bpf_printk("dname: %s\n", dname.full);
    struct dns_qrr *qrr;
    if (!(qrr = parse_dns_qrr(c)))
        return XDP_PASS;

    // now check for a valid OPT record
    // TODO: what if there is no OPT? add a bit 'no EDNS?'

    if (!(c->pos < c->end))
        return XDP_PASS; // no OPT record
    if (*(uint8_t *)c->pos != 0x00){
        bpf_printk("expected name root (0x00), XDP_PASS");
        return XDP_PASS;
    }

    c->pos += 1;
    struct dns_rr *opt;

    if (!(opt = parse_dns_rr(c))
        || __bpf_ntohs(opt->type) != RR_TYPE_OPT) {
        return XDP_PASS; // not an OPT record
    }


    if (__bpf_ntohl(opt->ttl) >> 15){ // & 0x1 ;
        bpf_printk("setting do_bit to 1\n");
        sk.do_bit = 1;
    }
    uint16_t edns_size = __bpf_ntohs(opt->class);

    if (edns_size <= 1231) {
        sk.edns_size_leq1231 = 1;
    } else if (edns_size == 1232) {
        sk.edns_size_1232 = 1;
    } else if (edns_size <= 1399) {
        sk.edns_size_leq1399 = 1;
    } else if (edns_size == 1400) {
        sk.edns_size_1400 = 1;
    } else if (edns_size <= 1499) {
        sk.edns_size_leq1499 = 1;
    } else if (edns_size == 1500) {
        sk.edns_size_1500 = 1;
    } else {
        sk.edns_size_gt1500 = 1;
    }





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

SEC("xdp-telemetry-ingress")
int xdp_telemetry_ingress(struct xdp_md *ctx)
{

	struct cursor     c;
	uint16_t          eth_proto;
	struct ethhdr    *eth;
	struct ipv6hdr   *ipv6;
	struct iphdr     *ipv4;
	struct udphdr    *udp;
	struct dnshdr    *dns;

	cursor_init(&c, ctx);
	if (!(eth = parse_eth(&c, &eth_proto)))
		return XDP_PASS;

	if (eth_proto == __bpf_htons(ETH_P_IPV6)) {
		if (!(ipv6 = parse_ipv6hdr(&c))
		||  !(ipv6->nexthdr == IPPROTO_UDP)
	 	||  !(udp = parse_udphdr(&c))
		||  !(udp->dest == __bpf_htons(DNS_PORT))
	 	||  !(dns = parse_dnshdr(&c))
        )
	 		return XDP_PASS;

		//bpf_printk("IPv6 DNS query\n");
		update_stats(&c, 1, udp, dns);

	} else if (eth_proto == __bpf_htons(ETH_P_IP)) {
        if (!(ipv4 = parse_iphdr(&c))
        ||  !(ipv4->protocol == IPPROTO_UDP)
        ||  !(udp = parse_udphdr(&c))
        ||  !(udp->dest == __bpf_htons(DNS_PORT))
        ||  !(dns = parse_dnshdr(&c))
        )
            return XDP_PASS; /* Not DNS */

		//bpf_printk("IPv4 DNS query\n");
		update_stats( &c, 0, udp, dns);
	}
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
