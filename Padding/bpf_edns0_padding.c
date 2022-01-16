/*
 * Copyright (c) 2021, NLnet Labs. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include <linux/pkt_cls.h>    /* for TC_ACT_OK*/
#include "bpf_edns0_padding.h"
#include "bpf-dns.h"

#define PAD_SIZE 468

struct bpf_elf_map jmp_map SEC("maps") = {
        .type           = BPF_MAP_TYPE_PROG_ARRAY,
        .id             = 1,
        .size_key       = sizeof(uint32_t),
        .size_value     = sizeof(uint32_t),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem       = 2,
};

SEC("1/0")
int tc_edns0_padding_egress(struct __sk_buff *skb)
{
	struct cursor     c;
	uint16_t          eth_proto;
	struct ethhdr    *eth;
	struct ipv6hdr   *ipv6;
	struct iphdr     *ipv4;
	struct udphdr    *udp;
	struct dnshdr    *dns;
	uint16_t          pkt_end = skb->data_end - skb->data;

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

		bpf_printk("IPv6 DNS response");

		struct query_v6 q;
		memcpy(&q.addr, &ipv6->saddr, sizeof(q.addr));
		q.port = udp->dest;
		q.id = dns->id;

		if (!bpf_map_delete_elem(&queries_v6, &q)) {
			uint16_t msg_sz = c.end - (void *)dns + 4;
			uint16_t pad_size = PAD_SIZE - (msg_sz % PAD_SIZE);
			uint16_t to_grow = 4 + pad_size;
			uint16_t pad_opt[2] = { __bpf_ntohs(OPT_CODE_PADDING)
			                      , __bpf_ntohs(pad_size) };

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

    			bpf_tail_call(skb, &jmp_map, 1);
			bpf_printk("IPv6 bpf_tail_call() failed");
		}

	} else if (eth_proto == __bpf_htons(ETH_P_IP)) {
		if (!(ipv4 = parse_iphdr(&c))
		||  !(ipv4->protocol == IPPROTO_UDP)
	 	||  !(udp = parse_udphdr(&c))
		||  !(udp->source == __bpf_htons(DNS_PORT))
	 	||  !(dns = parse_dnshdr(&c))
		||  !__bpf_ntohs(dns->arcount))
	 		return TC_ACT_OK; /* Not DNS */

		bpf_printk("IPv4 DNS response");

		struct query_v4 q;
		q.addr = ipv4->saddr;
		q.port = udp->dest;
		q.id = dns->id;

		if (!bpf_map_delete_elem(&queries_v4, &q)) {
			uint16_t msg_sz = c.end - (void *)dns + 4;
			uint16_t pad_size = PAD_SIZE - (msg_sz % PAD_SIZE);
			uint16_t to_grow = 4 + pad_size;
			uint16_t pad_opt[2] = { __bpf_ntohs(OPT_CODE_PADDING)
			                      , __bpf_ntohs(pad_size) };

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
    			bpf_tail_call(skb, &jmp_map, 1);
			bpf_printk("IPv4 bpf_tail_call() failed");
		}
	}
	return TC_ACT_OK;
}

SEC("1/1")
int skip_resource_records(struct __sk_buff *skb)
{
	struct cursor     c;
	uint8_t          *dname;
	struct dns_rr    *rr;

	cursor_init_skb(&c, skb);
	if (skb->cb[1] > 1500)
		return TC_ACT_OK;
	c.pos += skb->cb[1];

	if (!(dname = skip_dname(&c))
	||  !(rr = parse_dns_rr(&c))
	||  __bpf_ntohs(rr->rdata_len) > 1500)
		return TC_ACT_OK;
	c.pos += __bpf_ntohs(rr->rdata_len);

	bpf_printk("rr %u, type: %d", skb->cb[0], __bpf_ntohs(rr->type));
	if (skb->cb[0] > 0) {
		skb->cb[0] -= 1;
		skb->cb[1] = c.pos - (void *)(long)skb->data;
		bpf_tail_call(skb, &jmp_map, 1);
		bpf_printk("bpf_tail_call failed");
	} else {
		bpf_printk("have all answers & authoritative");
		bpf_printk("to_grow: %d\n", c.end - c.pos);
		rr->rdata_len = __bpf_htons(__bpf_ntohs(rr->rdata_len) + (c.end - c.pos));
	}
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

