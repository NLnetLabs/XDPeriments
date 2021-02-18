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
#include "bpf_edns0_padding.h"
#include "bpf-dns.h"

#define MAX_NUM_OPTIONS    6 
#define MAX_OPTION_LEN  1500

SEC("xdp-edns0-padding-ingress")
int xdp_edns0_padding_ingress(struct xdp_md *ctx)
{
	struct cursor     c;
	uint16_t          eth_proto;
	struct ethhdr    *eth;
	struct ipv6hdr   *ipv6;
	struct iphdr     *ipv4;
	struct udphdr    *udp;
	struct dnshdr    *dns;
	struct dns_rr    *opt_rr;
	uint16_t          rdata_len;
	uint8_t           i;

	cursor_init(&c, ctx);
	if (!(eth = parse_eth(&c, &eth_proto)))
		return XDP_PASS;

	if (eth_proto == __bpf_htons(ETH_P_IPV6)) {
		if (!(ipv6 = parse_ipv6hdr(&c))
		||  !(ipv6->nexthdr == IPPROTO_UDP)
	 	||  !(udp = parse_udphdr(&c))
		||  !(udp->dest == __bpf_htons(DNS_PORT))
	 	||  !(dns = parse_dnshdr(&c)))
	 		return XDP_PASS; /* Not DNS */

		if (dns->flags.as_bits_and_pieces.qr
		||  dns->qdcount != __bpf_htons(1)
		||  dns->ancount || dns->nscount
		||  dns->arcount >  __bpf_htons(2)
		||  !skip_dname(&c)
		||  !parse_dns_qrr(&c))
			return XDP_PASS; // Return FORMERR?

		if (dns->arcount == 0)
			return XDP_PASS;

		if (c.pos + 1 > c.end
		||  *(uint8_t *)c.pos != 0)
			return XDP_PASS; // Return FORMERR?
		c.pos += 1;

		if (!(opt_rr = parse_dns_rr(&c))
		||    opt_rr->type != __bpf_htons(RR_TYPE_OPT))
			return XDP_PASS;

		rdata_len = __bpf_ntohs(opt_rr->rdata_len);
		for (i = 0; i < MAX_NUM_OPTIONS && rdata_len >= 4; i++) {
			struct option *opt;
			uint16_t       opt_len;

			if (!(opt = parse_option(&c)))
				return XDP_ABORTED;

			bpf_printk("IPv6 OPT code: %d, len: %d\n"
			          , __bpf_ntohs(opt->code)
				  , __bpf_ntohs(opt->len));

			rdata_len -= 4;
			opt_len = __bpf_ntohs(opt->len);
			if (opt->code == __bpf_htons(OPT_CODE_PADDING)) {
				struct query_v6 q;
				uint8_t one = 1;
				
				memcpy(&q.addr, &ipv6->saddr, sizeof(q.addr));
				q.port = udp->source;
				q.id = dns->id;
				bpf_map_update_elem( &queries_v6
				                   , &q, &one, BPF_ANY);
				bpf_printk("IPv6 padding option found\n");
				return XDP_PASS;
			}
			if (opt_len > MAX_OPTION_LEN || opt_len > rdata_len
			||  c.pos + opt_len > c.end)
				return XDP_PASS;

			rdata_len -= opt_len;
			c.pos += opt_len;
		}
	} else if (eth_proto == __bpf_htons(ETH_P_IP)) {
		if (!(ipv4 = parse_iphdr(&c))
		||  !(ipv4->protocol == IPPROTO_UDP)
	 	||  !(udp = parse_udphdr(&c))
		||  !(udp->dest == __bpf_htons(DNS_PORT))
	 	||  !(dns = parse_dnshdr(&c)))
	 		return XDP_PASS; /* Not DNS */
	 		
		if (dns->flags.as_bits_and_pieces.qr
		||  dns->qdcount != __bpf_htons(1)
		||  dns->ancount || dns->nscount
		||  dns->arcount >  __bpf_htons(2)
		||  !skip_dname(&c)
		||  !parse_dns_qrr(&c))
			return XDP_PASS; // return FORMERR?

		if (dns->arcount == 0) 
			return XDP_PASS;

		if (c.pos + 1 > c.end
		||  *(uint8_t *)c.pos != 0)
			return XDP_PASS;
		c.pos += 1;

		if (!(opt_rr = parse_dns_rr(&c))
		||    opt_rr->type != __bpf_htons(RR_TYPE_OPT))
			return XDP_PASS;

		rdata_len = __bpf_ntohs(opt_rr->rdata_len);
		for (i = 0; i < MAX_NUM_OPTIONS && rdata_len >= 4; i++) {
			struct option *opt;
			uint16_t       opt_len;

			if (!(opt = parse_option(&c)))
				return XDP_ABORTED;

			bpf_printk("IPv4 OPT code: %d, len: %d\n"
			          , __bpf_ntohs(opt->code)
				  , __bpf_ntohs(opt->len));

			rdata_len -= 4;
			opt_len = __bpf_ntohs(opt->len);
			if (opt->code == __bpf_htons(OPT_CODE_PADDING)) {
				struct query_v4 q;
				uint8_t one = 1;
				
				q.addr = ipv4->saddr;
				q.port = udp->source;
				q.id = dns->id;
				bpf_map_update_elem( &queries_v4
				                   , &q, &one, BPF_ANY);
				bpf_printk("IPv4 padding option found\n");
				return XDP_PASS;
			}
			if (opt_len > MAX_OPTION_LEN || opt_len > rdata_len
			||  c.pos + opt_len > c.end)
				return XDP_PASS;

			rdata_len -= opt_len;
			c.pos += opt_len;
		}
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

