/*
 * Copyright (c) 2020, NLnet Labs. All rights reserved.
 * 
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h> /* for struct ethhdr   */
#include <linux/ip.h>       /* for struct iphdr    */
#include <linux/ipv6.h>     /* for struct ipv6hdr  */
#include <linux/in.h>       /* for IPPROTO_UDP     */
#include <linux/udp.h>      /* for struct udphdr   */
#include <bpf_helpers.h>
#include <bpf_endian.h>

// do not use libc includes because this causes clang 
// to include 32bit headers on 64bit ( only ) systems.
typedef __u8 uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
#define memcpy __builtin_memcpy

#define DNS_PORT      53
#define RR_TYPE_OPT   41
#define RCODE_REFUSED  5

struct vlanhdr {
	uint16_t tci;
	uint16_t encap_proto;
};

struct dnshdr {
	uint16_t id;
	uint8_t  rd     : 1;
	uint8_t  tc     : 1;
	uint8_t  aa     : 1;
	uint8_t  opcode : 4;
	uint8_t  qr     : 1;
	uint8_t  rcode  : 4;
	uint8_t  cd     : 1;
	uint8_t  ad     : 1;
	uint8_t  z      : 1;
	uint8_t  ra     : 1;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};

struct dns_qrr {
        uint16_t qtype;
        uint16_t qclass;
};

struct dns_rr {
        uint16_t type;
        uint16_t class;
        uint32_t ttl;
        uint16_t rdata_len;
} __attribute__((packed));

struct cursor {
	void *pos;
	void *end;
};

static __always_inline
void cursor_init(struct cursor *c, struct xdp_md *ctx)
{
	c->end = (void *)(long)ctx->data_end;
	c->pos = (void *)(long)ctx->data;
}

#define PARSE_FUNC_DECLARATION(STRUCT)			\
static __always_inline					\
struct STRUCT *parse_ ## STRUCT (struct cursor *c)	\
{							\
	struct STRUCT *ret = c->pos;			\
	if (c->pos + sizeof(struct STRUCT) > c->end)	\
		return 0;				\
	c->pos += sizeof(struct STRUCT);		\
	return ret;					\
}

PARSE_FUNC_DECLARATION(ethhdr)
PARSE_FUNC_DECLARATION(vlanhdr)
PARSE_FUNC_DECLARATION(iphdr)
PARSE_FUNC_DECLARATION(ipv6hdr)
PARSE_FUNC_DECLARATION(udphdr)
PARSE_FUNC_DECLARATION(dnshdr)
PARSE_FUNC_DECLARATION(dns_qrr)
PARSE_FUNC_DECLARATION(dns_rr)

static __always_inline
struct ethhdr *parse_eth(struct cursor *c, uint16_t *eth_proto)
{
	struct ethhdr  *eth;

	if (!(eth = parse_ethhdr(c)))
		return 0;
       
	*eth_proto = eth->h_proto;
	if (*eth_proto == __bpf_htons(ETH_P_8021Q)
	||  *eth_proto == __bpf_htons(ETH_P_8021AD)) {
		struct vlanhdr *vlan;

		if (!(vlan = parse_vlanhdr(c)))
			return 0;

		*eth_proto = vlan->encap_proto;
		if (*eth_proto == __bpf_htons(ETH_P_8021Q)
		||  *eth_proto == __bpf_htons(ETH_P_8021AD)) {
			if (!(vlan = parse_vlanhdr(c)))
				return 0;

			*eth_proto = vlan->encap_proto;
		}
	}
	return eth;
}

static __always_inline
uint8_t *parse_dname(struct cursor *c, uint8_t *pkt)
{
        uint8_t *dname = c->pos;

        int  i;
        for (i = 0; i < 40; i++) { /* Maximum 128 labels */
                uint8_t o;

                if (c->pos + 1 > c->end)
                        return 0;

                o = *(uint8_t *)c->pos;
                if ((o & 0xC0) == 0xC0) {
                        /* Compression label, Only back references! */
                        if ((o | 0x3F) >= (dname - pkt))
                                return 0;

                        /* Compression label is last label of dname. */
                        c->pos += 1;
                        break;

                } else if (o & 0xC0)
                        /* Unknown label type */
                        return 0;

                c->pos += o + 1;
                if (!o)
                        break;
        }
        return dname;
}

static __always_inline
enum xdp_action udp_dns_reply(struct cursor *c, struct udphdr **udp)
{
	struct dnshdr  *dns;
	uint8_t        *qname;
	struct dns_qrr *qrr;
	uint8_t        *opt_owner;
	struct dns_rr  *opt_rr;
	uint32_t        csum;

	if (!(*udp = parse_udphdr(c)) || (*udp)->dest != __bpf_htons(DNS_PORT)
	||  !(dns = parse_dnshdr(c)))
		return XDP_PASS;

	if (dns->qr
	||  dns->qdcount != __bpf_htons(1)
	||  dns->ancount || dns->nscount
	||  dns->arcount >  __bpf_htons(1)
	||  !(qname = parse_dname(c, (void *)dns))
	||  !(qrr = parse_dns_qrr(c)))
		return XDP_ABORTED;

	csum = ~((uint32_t)(*udp)->check);
	if (dns->arcount) {
		opt_owner = c->pos;
		if (++c->pos > c->end || *opt_owner
		|| !(opt_rr = parse_dns_rr(c))
		||   opt_rr->type != __bpf_htons(RR_TYPE_OPT))
			return XDP_ABORTED;

		if (opt_rr->rdata_len == 0)
			; /* pass */

		else if (c->pos + 1 > c->end)
			return XDP_ABORTED;

		else if (((void *)&opt_rr->rdata_len - (void *)dns) % 2 == 1) {
			csum = bpf_csum_diff(c->pos - 3, 4, 0, 0, csum);
			opt_rr->rdata_len = 0;
			csum = bpf_csum_diff(0, 0, c->pos - 3, 4, csum);
		} else {
			csum = bpf_csum_diff(c->pos - 4, 4, 0, 0, csum);
			opt_rr->rdata_len = 0;
			csum = bpf_csum_diff(0, 0, c->pos - 4, 4, csum);
		}
	}
	csum = bpf_csum_diff((void *)dns, 4, 0, 0, csum);
	dns->ad = 0;
	dns->qr = 1;
	dns->rcode = RCODE_REFUSED;
	csum = bpf_csum_diff(0, 0, (void *)dns, 4, csum);

	(*udp)->dest   = (*udp)->source;
	(*udp)->source = __bpf_htons(DNS_PORT);
	csum = (csum & 0xFFFF) + (csum >> 16);
	csum = (csum & 0xFFFF) + (csum >> 16);
	(*udp)->check = ~csum;
	return XDP_TX;
}

static __always_inline
void csum_remove_data(uint32_t *csum, struct cursor *c, uint16_t len)
{
	if (c->pos + len <= c->end) {
		*csum = bpf_csum_diff(c->pos, len, 0, 0, *csum);
		c->pos += len;
	}
}

SEC("xdp-dns-says-no-v3")
int xdp_dns_says_no(struct xdp_md *ctx)
{
	struct cursor   c;
	struct ethhdr  *eth;
	uint16_t        eth_proto;
	struct iphdr   *ipv4;
	struct ipv6hdr *ipv6;
	struct udphdr  *udp;
	enum xdp_action action = XDP_PASS;
	uint16_t        to_strip = 0;

	cursor_init(&c, ctx);
	if (!(eth = parse_eth(&c, &eth_proto)))
		return XDP_PASS;

	if (eth_proto == __bpf_htons(ETH_P_IP)) {
		if (!(ipv4 = parse_iphdr(&c))
		||    ipv4->protocol != IPPROTO_UDP
		||   (action = udp_dns_reply(&c, &udp)) != XDP_TX)
			return action;

		uint32_t swap_ipv4 = ipv4->daddr;
		ipv4->daddr = ipv4->saddr;
		ipv4->saddr = swap_ipv4;

		to_strip = c.end - c.pos;
		if (to_strip > 0) {
			uint32_t old_ipv4_len = ipv4->tot_len;
			uint32_t new_ipv4_len = __bpf_htons(__bpf_ntohs(old_ipv4_len) - to_strip);
			uint32_t csum = ~((uint32_t)ipv4->check);

			ipv4->tot_len = new_ipv4_len;
			csum = bpf_csum_diff(&old_ipv4_len, 4, &new_ipv4_len, 4, csum);
			csum = (csum & 0xFFFF) + (csum >> 16);
			csum = (csum & 0xFFFF) + (csum >> 16);
			ipv4->check = ~csum;

			udp->len = __bpf_htons(__bpf_ntohs(udp->len) - to_strip);
			udp->check = 0;
		}

	} else if (eth_proto == __bpf_htons(ETH_P_IPV6)) {
		if (!(ipv6 = parse_ipv6hdr(&c))
		||    ipv6->nexthdr  != IPPROTO_UDP
		||   (action = udp_dns_reply(&c, &udp)) != XDP_TX)
			return action;

		struct in6_addr swap_ipv6 = ipv6->daddr;
		ipv6->daddr = ipv6->saddr;
		ipv6->saddr = swap_ipv6;

		to_strip = c.end - c.pos;
		if (to_strip > 0 && to_strip < 0x80) {
			uint32_t old_udp_len  = udp->len;
			uint32_t new_udp_len  = __bpf_htons(__bpf_ntohs(udp->len) - to_strip);
			uint32_t old_ipv6_len = ipv6->payload_len;
			uint32_t new_ipv6_len = __bpf_htons(__bpf_ntohs(old_ipv6_len) - to_strip);
			uint32_t csum = ~((uint32_t)udp->check);


			ipv6->payload_len = new_ipv6_len;
			udp->len = new_udp_len;
			csum = bpf_csum_diff(&old_ipv6_len, 4, &new_ipv6_len, 4, csum);
			csum = bpf_csum_diff(&old_udp_len , 4, &new_udp_len , 4, csum);

			if ((c.pos - (void *)udp) % 2 == 1)
				c.pos -= 1;

			csum_remove_data(&csum, &c, 0x40);
			csum_remove_data(&csum, &c, 0x20);
			csum_remove_data(&csum, &c, 0x10);
			csum_remove_data(&csum, &c, 0x08);
			csum_remove_data(&csum, &c, 0x04);
			if (c.pos + 0x02 <= c.end) {
				uint32_t old_val = *(uint8_t *)c.pos;
				csum = bpf_csum_diff(&old_val, 4, 0, 0, csum);
				c.pos += 2;
			}
			if (c.pos + 0x01 <= c.end) {
				uint32_t old_val = *(uint8_t *)c.pos;
				csum = bpf_csum_diff(&old_val, 4, 0, 0, csum);
			}
			csum = (csum & 0xFFFF) + (csum >> 16);
			csum = (csum & 0xFFFF) + (csum >> 16);
			udp->check = ~csum;
		}
	} else
		return XDP_PASS;

	uint8_t swap_eth[ETH_ALEN];
	memcpy(swap_eth, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, swap_eth, ETH_ALEN);

	if (to_strip > 0)
		bpf_xdp_adjust_tail(ctx, -(int)to_strip);

	return XDP_TX;
}
