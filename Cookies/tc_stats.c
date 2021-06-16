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

static __always_inline
int update_dnames(struct bpf_elf_map* dnames, struct cursor* c, struct __sk_buff* skb)
{
    
		void *dname_start =  c->pos;
		skip_dname(c);
		void *dname_end =  c->pos;

		uint32_t dname_len = (uint32_t)(dname_end - dname_start);

		char dname[255] = {0};
        char * dnameptr = dname;

        uint32_t offset = (uint32_t)(dname_start - (void *)(long)skb->data);
        void *to = dnameptr;
        LOAD_DNAME(128);
        LOAD_DNAME(64);
        LOAD_DNAME(32);
        LOAD_DNAME(16);
        LOAD_DNAME(8);
        LOAD_DNAME(4);
        LOAD_DNAME(2);
        LOAD_DNAME(1);

		uint64_t *dnamep = bpf_map_lookup_elem(dnames, &dname);
		if (dnamep) {
			*dnamep += 1;
			//bpf_printk("existing dname %s, value %i", &dname, *dnamep);
		} else {
			//bpf_printk("new dname %s, inserting..", &dname);
			uint64_t new_value = 1;
			bpf_map_update_elem(dnames, &dname, &new_value, 0);
		}

    //return TC_ACT_OK;
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
