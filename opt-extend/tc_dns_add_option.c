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
#include <iproute2/bpf_elf.h> /* for struct bpf_elf_map */
#include <bpf_helpers.h>      /* for SEC */
#include "bpf-dns.h"

#define REPORT_DOMAIN "\x06report\x09nlnetlabs\x02nl\x00"
#define OPT_CODE_EDER 65001 /* first experimental opt code from: RFC6891 */
#define RANDOM_CHANCE 100 /* sampling rate of the EDER code in percentage*/

struct bpf_elf_map eder_map SEC("maps") = {
        .type           = BPF_MAP_TYPE_PROG_ARRAY,
        .id             = 1,
        .size_key       = sizeof(uint32_t),
        .size_value     = sizeof(uint32_t),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem       = 2,
};

SEC("1/0")
int tc_edns0_option_egress(struct __sk_buff *skb)
{
	struct cursor     c;
	uint16_t          eth_proto;
	struct ethhdr    *eth;
	struct ipv6hdr   *ipv6;
	struct iphdr     *ipv4;
	struct udphdr    *udp;
	struct dnshdr    *dns;
	uint16_t          pkt_end = skb->data_end - skb->data;
	uint32_t          old_len, new_len, csum;
	static struct {
		uint16_t opt_code;
		uint16_t opt_len;
		uint8_t  opt_data[sizeof(REPORT_DOMAIN)];
	} option = {
		__bpf_ntohs(65001)
	      , __bpf_ntohs(sizeof(REPORT_DOMAIN))
	      , REPORT_DOMAIN 
	};

	cursor_init_skb(&c, skb);
	if (!(eth = parse_eth(&c, &eth_proto)))
		return TC_ACT_OK;

	if (eth_proto == __bpf_htons(ETH_P_IPV6)) {
		if (!(ipv6 = parse_ipv6hdr(&c))
		||  !(ipv6->nexthdr == IPPROTO_UDP)
	 	||  !(udp = parse_udphdr(&c))
		||  !(udp->source == __bpf_htons(DNS_PORT))
	 	||  !(dns = parse_dnshdr(&c))
		||  !__bpf_ntohs(dns->arcount)
		||  bpf_get_prandom_u32() % 100 > RANDOM_CHANCE
		|| !skip_dname(&c)
		|| !parse_dns_qrr(&c))
	 		return TC_ACT_OK; /* Pass */

		skb->cb[0] = __bpf_ntohs(dns->ancount)
		           + __bpf_ntohs(dns->nscount)
		           + __bpf_ntohs(dns->arcount) -1;
		skb->cb[1] = c.pos - (void *)(long)skb->data;

		old_len = udp->len;
		new_len = __bpf_htons(__bpf_ntohs(old_len) + sizeof(option));
		csum = ~((uint32_t)udp->check);

		ipv6->payload_len = udp->len = new_len;
		csum = bpf_csum_diff( &new_len, sizeof(new_len)
		                    , &old_len, sizeof(old_len), csum);
		csum = (csum & 0xFFFF) + (csum >> 16);
		csum = (csum & 0xFFFF) + (csum >> 16);
		udp->check = ~csum;

		bpf_skb_change_tail( skb, pkt_end + sizeof(option), 0);
		bpf_skb_store_bytes( skb, pkt_end, &option, sizeof(option), 0);
    		bpf_tail_call(skb, &eder_map, 1);
		bpf_printk("IPv6 bpf_tail_call() failed\n");

	} else if (eth_proto == __bpf_htons(ETH_P_IP)) {
		if (!(ipv4 = parse_iphdr(&c))
		||  !(ipv4->protocol == IPPROTO_UDP)
	 	||  !(udp = parse_udphdr(&c))
		||  !(udp->source == __bpf_htons(DNS_PORT))
	 	||  !(dns = parse_dnshdr(&c))
		||  !__bpf_ntohs(dns->arcount)
		||  bpf_get_prandom_u32() % 100 > RANDOM_CHANCE
		|| !skip_dname(&c)
		|| !parse_dns_qrr(&c))
	 		return TC_ACT_OK; /* Pass */

		skb->cb[0] = __bpf_ntohs(dns->ancount)
		           + __bpf_ntohs(dns->nscount)
		           + __bpf_ntohs(dns->arcount) -1;
		skb->cb[1] = c.pos - (void *)(long)skb->data;

		old_len = ipv4->tot_len;
		new_len = __bpf_htons(__bpf_ntohs(ipv4->tot_len) + sizeof(option));
		csum = ~((uint32_t)ipv4->check);

		ipv4->tot_len = new_len;
		csum = bpf_csum_diff( &old_len, sizeof(old_len)
		                    , &new_len, sizeof(new_len), csum);
		csum = (csum & 0xFFFF) + (csum >> 16);
		csum = (csum & 0xFFFF) + (csum >> 16);
		ipv4->check = ~csum;

		old_len = udp->len;
		new_len = __bpf_htons(__bpf_ntohs(old_len) + sizeof(option));
		csum = ~((uint32_t)udp->check);
		udp->len = new_len;
		csum = bpf_csum_diff( &new_len, sizeof(new_len)
		                    , &old_len, sizeof(old_len), csum);
		csum = (csum & 0xFFFF) + (csum >> 16);
		csum = (csum & 0xFFFF) + (csum >> 16);
		udp->check = ~csum;

		bpf_skb_change_tail( skb, pkt_end + sizeof(option), 0);
		bpf_skb_store_bytes( skb, pkt_end, &option, sizeof(option), 0);
    		bpf_tail_call(skb, &eder_map, 1);
		bpf_printk("IPv4 bpf_tail_call() failed\n");
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

	if (skb->cb[0] > 0) {
		skb->cb[0] -= 1;
		skb->cb[1] = c.pos - (void *)(long)skb->data;
		bpf_tail_call(skb, &eder_map, 1);
		bpf_printk("bpf_tail_call failed\n");

	} else if (__bpf_ntohs(rr->type) == RR_TYPE_OPT) {
		rr->rdata_len = __bpf_htons(
				__bpf_ntohs(rr->rdata_len) + (c.end - c.pos));
	}
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

