#include <linux/pkt_cls.h>    /* for TC_ACT_OK*/
#include <iproute2/bpf_elf.h> /* for struct bpf_elf_map */
#include <linux/bpf.h>        /* of bpf_helpers.h */
#include <bpf_helpers.h>      /* for SEC */
#include "bpf-dns.h"
#include "tc_stats.h"

struct bpf_elf_map jmp_map SEC("maps") = {
        .type           = BPF_MAP_TYPE_PROG_ARRAY,
        .id             = 1,
        .size_key       = sizeof(uint32_t),
        .size_value     = sizeof(uint32_t),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem       = 1,
};

//int update_stats(struct bpf_elf_map* rcodes_v4, struct dnshdr* dns)
//SEC("1/0")
//int noop()
//{
//	return TC_ACT_OK;
//}

SEC("do-update-stats")
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
		bpf_printk("rcodes %i seen: %i\n", rcode, *current_rcode_count);
	}

	uint32_t size_key = __bpf_ntohs(udp->len);
	bpf_printk("udp->len: %i", size_key);
	uint64_t* current_size_count = bpf_map_lookup_elem(response_sizes, &size_key);
	if (current_size_count) {
		*current_size_count += 1;
		bpf_printk("size %i seen: %i", size_key, *current_size_count);
	}
	
    return TC_ACT_OK;
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
	//uint16_t          pkt_end = skb->data_end - skb->data;

	cursor_init_skb(&c, skb);
	if (!(eth = parse_eth(&c, &eth_proto)))
		return TC_ACT_OK;

	if (eth_proto == __bpf_htons(ETH_P_IPV6)) {
		if (!(ipv6 = parse_ipv6hdr(&c))
		||  !(ipv6->nexthdr == IPPROTO_UDP)
	 	||  !(udp = parse_udphdr(&c))
		||  !(udp->source == __bpf_htons(DNS_PORT))
	 	||  !(dns = parse_dnshdr(&c))
		||  !__bpf_ntohs(dns->arcount))
	 		return TC_ACT_OK; /* Not DNS with OPT RR*/

		bpf_printk("IPv6 DNS response\n");
		update_stats(&rcodes_v6, &response_sizes_v6, udp, dns);

/*
		struct query_v6 q;
		memcpy(&q.addr, &ipv6->saddr, sizeof(q.addr));
		q.port = udp->dest;
		q.id = dns->id;

		if (!bpf_map_delete_elem(&queries_v6, &q)) {
			uint16_t msg_sz = c.end - (void *)dns + 4;
			uint16_t pad_len = 468 - (msg_sz % 468);
			uint16_t to_grow = 4 + pad_len;
			uint16_t pad_opt[2] = { __bpf_ntohs(OPT_CODE_PADDING)
			                      , __bpf_ntohs(pad_len) };

			if (!skip_dname(&c) || !parse_dns_qrr(&c))
				return TC_ACT_OK;

			skb->cb[0] = __bpf_ntohs(dns->ancount)
			           + __bpf_ntohs(dns->nscount)
			           + __bpf_ntohs(dns->arcount) - 1;
			skb->cb[1] = c.pos - (void *)(long)skb->data;

			ipv6->payload_len = udp->len =
				__bpf_htons(__bpf_ntohs(udp->len)+ to_grow);

			bpf_skb_change_tail( skb, pkt_end + to_grow, 0);
			bpf_skb_store_bytes( skb, pkt_end, pad_opt, 4
			                   , BPF_F_RECOMPUTE_CSUM);

    			bpf_tail_call(skb, &jmp_map, 0);
			bpf_printk("IPv6 bpf_tail_call() failed\n");
		}
*/

	} else if (eth_proto == __bpf_htons(ETH_P_IP)) {
		if (!(ipv4 = parse_iphdr(&c))
		||  !(ipv4->protocol == IPPROTO_UDP)
	 	||  !(udp = parse_udphdr(&c))
		||  !(udp->source == __bpf_htons(DNS_PORT))
	 	||  !(dns = parse_dnshdr(&c))
		||  !__bpf_ntohs(dns->arcount))
	 		return TC_ACT_OK; /* Not DNS */

		bpf_printk("IPv4 DNS response\n");
		//update_stats(&rcodes_v4, udp, dns);
		update_stats(&rcodes_v4, &response_sizes_v4, udp, dns);
/*
		uint32_t rcode = (uint32_t) dns->flags.as_bits_and_pieces.rcode;
		//uint8_t key = {rcode};
    	bpf_printk("in update_stats for outgoing packet, rcode %i\n", rcode);

		uint64_t* current_rcode_count = bpf_map_lookup_elem(&rcodes_v4, &rcode);
		if (current_rcode_count) {
			*current_rcode_count += 1;
			bpf_printk("rcodes %i seen: %i\n", rcode, *current_rcode_count);
		}
		update_stats(&rcodes_v4, 12);

		uint32_t size_key = __bpf_ntohs(udp->len);
		bpf_printk("udp->len: %i", size_key);
		uint64_t* current_size_count = bpf_map_lookup_elem(&response_sizes_v4, &size_key);
		if (current_size_count) {
			*current_size_count += 1;
			bpf_printk("size %i seen: %i", size_key, *current_size_count);
		}
*/
		
		//bpf_map_update_elem(&rcodes_v4, dns->flags.as_bits_and_pieces.rcode, += 1;

		//update_stats(&rcodes_v4, dns->flags.as_bits_and_pieces.rcode);

/*
		struct query_v4 q;
		q.addr = ipv4->saddr;
		q.port = udp->dest;
		q.id = dns->id;

		if (!bpf_map_delete_elem(&queries_v4, &q)) {
			uint16_t msg_sz = c.end - (void *)dns + 4;
			uint16_t pad_len = 468 - (msg_sz % 468);
			uint16_t to_grow = 4 + pad_len;
			uint16_t pad_opt[2] = { __bpf_ntohs(OPT_CODE_PADDING)
			                      , __bpf_ntohs(pad_len) };

			if (!skip_dname(&c) || !parse_dns_qrr(&c))
				return TC_ACT_OK;

			skb->cb[0] = __bpf_ntohs(dns->ancount)
			           + __bpf_ntohs(dns->nscount)
			           + __bpf_ntohs(dns->arcount) - 1;
			skb->cb[1] = c.pos - (void *)(long)skb->data;

			uint32_t old_len = ipv4->tot_len;
			uint32_t new_len = __bpf_htons(
					__bpf_ntohs(ipv4->tot_len) + to_grow);
			uint32_t csum = ~((uint32_t)ipv4->check);

			ipv4->tot_len = new_len;
			csum = bpf_csum_diff( &old_len, sizeof(old_len)
			                    , &new_len, sizeof(new_len), csum);
			csum = (csum & 0xFFFF) + (csum >> 16);
			csum = (csum & 0xFFFF) + (csum >> 16);
			ipv4->check = ~csum;

			udp->len = __bpf_htons(__bpf_ntohs(udp->len)+ to_grow);

			bpf_skb_change_tail( skb, pkt_end + to_grow, 0);
			bpf_skb_store_bytes( skb, pkt_end, pad_opt, 4
			                   , BPF_F_RECOMPUTE_CSUM);
    			bpf_tail_call(skb, &jmp_map, 0);
			bpf_printk("IPv4 bpf_tail_call() failed\n");
		}
*/
	}
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
