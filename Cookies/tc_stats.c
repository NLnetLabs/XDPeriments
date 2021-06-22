#include <linux/pkt_cls.h>    /* for TC_ACT_OK*/
#include <iproute2/bpf_elf.h> /* for struct bpf_elf_map */
#include <linux/bpf.h>        /* of bpf_helpers.h */
#include <bpf_helpers.h>      /* for SEC */
#include "bpf-dns.h"
#include "tc_stats.h"

#define LOAD_DNAME(n) {\
    if (dname_len >= n) {\
        bpf_skb_load_bytes(skb, offset, to, n);\
        offset += n;\
        to += n;\
        dname_len -= n;\
    }\
}

//struct bpf_elf_map jmp_map SEC("maps") = {
//        .type           = BPF_MAP_TYPE_PROG_ARRAY,
//        .id             = 1,
//        .size_key       = sizeof(uint32_t),
//        .size_value     = sizeof(uint32_t),
//        .pinning        = PIN_GLOBAL_NS,
//        .max_elem       = 1,
//};

static __always_inline
int update_stats(
		struct bpf_elf_map* rcodes,
		struct bpf_elf_map* response_sizes,
		struct udphdr *udp,
		struct dnshdr *dns)
{
	uint32_t rcode = (uint32_t) dns->flags.as_bits_and_pieces.rcode;
	uint64_t* current_rcode_count = bpf_map_lookup_elem(rcodes, &rcode);
	if (current_rcode_count) {
		*current_rcode_count += 1;
		//bpf_printk("rcodes %i seen: %i\n", rcode, *current_rcode_count);
	}

	uint32_t size_key = __bpf_ntohs(udp->len);
	//bpf_printk("udp->len: %i", size_key);
	uint64_t* current_size_count = bpf_map_lookup_elem(response_sizes, &size_key);
	if (current_size_count) {
		*current_size_count += 1;
		//bpf_printk("size %i seen: %i", size_key, *current_size_count);
	}
	
    //return TC_ACT_OK;
    return 0;
}

#define COPY_DNAME(skb, offset, dst, dname_len, n) {\
    if (dname_len >= n) {\
        bpf_skb_load_bytes(skb, offset, dst, n);\
        offset += n;\
        dst += n;\
        dname_len -= n;\
    }\
}

#define COPY_TLD(skb, offset, dst, tld_len, n) {\
    if (tld_len == n) {\
        bpf_skb_load_bytes(skb, offset - tld_len + 1, res->tld, n - 1);\
    }\
}

// returns length of dname
// records the dname, length and tld offset in dname* res
static __always_inline
int parse_dname(struct dname *res, struct cursor *c, struct __sk_buff *skb)
{
    uint32_t offset = (uint32_t)(c->pos - (void *)(long)skb->data);

    res->len = 0;
    uint8_t tld_offset = 0;


    // determine total length of the dname, and the offset of the last label
    uint8_t i;
    for (i = 0; i < 128; i++) {
        if (c->pos + 1 > c->end) {
            bpf_printk("early return 1");
            return res->len;
        }

        uint8_t labellen;
        labellen = *(uint8_t*)c->pos;
        if (labellen == 0)
            break;

        tld_offset = res->len;

        if (c->pos + labellen + 1 > c->end) {
            bpf_printk("early return 2");
            return res->len;
        }
        res->len += labellen + 1;
        c->pos += labellen + 1;
    }

    // use LOAD_DNAME to copy 64/32/16 etc bytes

    void* to= res->full;
    uint32_t dname_len = res->len;

    COPY_DNAME(skb, offset, to, dname_len, 64);
    COPY_DNAME(skb, offset, to, dname_len, 32);
    COPY_DNAME(skb, offset, to, dname_len, 16);
    COPY_DNAME(skb, offset, to, dname_len, 8);
    COPY_DNAME(skb, offset, to, dname_len, 4);
    COPY_DNAME(skb, offset, to, dname_len, 2);
    COPY_DNAME(skb, offset, to, dname_len, 1);


    bpf_printk("dname len: %i", res->len);

    // now copy the .tld
    int tld_len = res->len - tld_offset;

    if (tld_len > 10) {
        bpf_skb_load_bytes(skb, offset - tld_len + 1, res->tld, 10);
    }

    COPY_TLD(skb, offset, res->tld, tld_len, 10); 
    COPY_TLD(skb, offset, res->tld, tld_len, 9); 
    COPY_TLD(skb, offset, res->tld, tld_len, 8); 
    COPY_TLD(skb, offset, res->tld, tld_len, 7); 
    COPY_TLD(skb, offset, res->tld, tld_len, 6); 
    COPY_TLD(skb, offset, res->tld, tld_len, 5); 
    COPY_TLD(skb, offset, res->tld, tld_len, 4); 
    COPY_TLD(skb, offset, res->tld, tld_len, 3); 
    
    //bpf_printk("returning full: %s", &res->full);
    //bpf_printk("returning tld: %s", &res->tld);
    return res->len;
}

static __always_inline
int update_dnames(struct bpf_elf_map* dnames, struct cursor* c, struct __sk_buff* skb)
{
        struct dname dname = {0};
        
        parse_dname(&dname, c, skb);
		uint64_t *tld_p = bpf_map_lookup_elem(&tlds, dname.tld);
        if (tld_p) {
            *tld_p += 1;
            //bpf_printk("existing TLD %s, now seen %i", dname.tld, *tld_p);
        } else {
            //bpf_printk("new TLD %s, inserting ..", dname.tld);
            uint64_t one = 1;
            if (bpf_map_update_elem(&tlds, dname.tld, &one, 0) < 0) {
                bpf_printk("failed to insert new TLD");
            }
        }


		uint64_t *dnamep = bpf_map_lookup_elem(dnames, dname.full);
		if (dnamep) {
			*dnamep += 1;
			//bpf_printk("existing dname %s, value %i", &dname, *dnamep);
		} else {
			bpf_printk("new dname %s, inserting..", &dname);
			uint64_t new_value = 1;
			if (bpf_map_update_elem(dnames, dname.full, &new_value, 0) < 0) {
                bpf_printk("error trying to insert new dname");
            } else {
                //bpf_printk("inserted, checking:");
                uint64_t *dnamep2 = bpf_map_lookup_elem(dnames, dname.full);
                if (!dnamep2) {
                    bpf_printk("FAILed to insert dname");
                } else {
                    //bpf_printk("success: %i", *dnamep2);
                }
            }
		}

    return 0;
}


SEC("tc-stats-egress")
int tc_stats_egress(struct __sk_buff *skb)
{
    //bpf_tail_call(skb, &jmp_map, 0);

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
	 	||  !(dns = parse_dnshdr(&c)))
	 		return TC_ACT_OK; /* Not DNS with OPT RR*/

		//bpf_printk("IPv6 DNS response\n");
		update_stats(&rcodes_v6, &response_sizes_v6, udp, dns);
        update_dnames(&dnames_v6, &c, skb);

	} else if (eth_proto == __bpf_htons(ETH_P_IP)) {
        if (!(ipv4 = parse_iphdr(&c))
        ||  !(ipv4->protocol == IPPROTO_UDP)
        ||  !(udp = parse_udphdr(&c))
        ||  !(udp->source == __bpf_htons(DNS_PORT))
        ||  !(dns = parse_dnshdr(&c)))
            return TC_ACT_OK; /* Not DNS */

		//bpf_printk("IPv4 DNS response\n");
		update_stats(&rcodes_v4, &response_sizes_v4, udp, dns);
        update_dnames(&dnames_v4, &c, skb);
	}
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
