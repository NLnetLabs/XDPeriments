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

// do not use libc includes because this causes clang 
// to include 32bit headers on 64bit ( only ) systems.
typedef __u8 uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
#define memcpy __builtin_memcpy

#define DNS_PORT      53
#define RCODE_REFUSED  5

#ifndef SEC
# define SEC(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#ifndef __always_inline
# define __always_inline                         \
   inline __attribute__((always_inline))
#endif

#ifndef __bpf_htons
# if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define __bpf_htons(x) __builtin_bswap16(x)
# else
#  define __bpf_htons(x) (x)
# endif
#endif

struct vlanhdr {
	uint16_t tci;
	uint16_t encap_proto;
};

struct dnshdr {
	uint16_t id;
	union {
		struct {
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
		}        as_bits_and_pieces;
		uint16_t as_value;
	} flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};

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
void update_checksum(uint16_t *csum, uint16_t old_val, uint16_t new_val)
{
	uint32_t new_csum_value;
	uint32_t new_csum_comp;
	uint32_t undo;

	undo = ~((uint32_t)*csum) + ~((uint32_t)old_val);
	new_csum_value = undo + (undo < ~((uint32_t)old_val)) + (uint32_t)new_val;
	new_csum_comp = new_csum_value + (new_csum_value < ((uint32_t)new_val));
	new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
	new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
	*csum = (uint16_t)~new_csum_comp;
}

static __always_inline
int udp_dns_reply(struct cursor *c)
{
	struct udphdr  *udp;
	struct dnshdr  *dns;

	if (!(udp = parse_udphdr(c))|| udp->dest != __bpf_htons(DNS_PORT)
	||  !(dns = parse_dnshdr(c)))
		return -1;

	uint16_t old_val = dns->flags.as_value;
	dns->flags.as_bits_and_pieces.ad = 0;
	dns->flags.as_bits_and_pieces.qr = 1;
	dns->flags.as_bits_and_pieces.rcode = RCODE_REFUSED;

	udp->dest   = udp->source;
	udp->source = __bpf_htons(DNS_PORT);

	update_checksum(&udp->check, old_val, dns->flags.as_value);
	return 0;
}

SEC("xdp-dns-says-no-v1")
int xdp_dns_says_no(struct xdp_md *ctx)
{
	struct cursor   c;
	struct ethhdr  *eth;
	uint16_t        eth_proto;
	struct iphdr   *ipv4;
	struct ipv6hdr *ipv6;

	cursor_init(&c, ctx);
	if (!(eth = parse_eth(&c, &eth_proto)))
		return XDP_PASS;

	if (eth_proto == __bpf_htons(ETH_P_IP)) {
		if (!(ipv4 = parse_iphdr(&c))
		||    ipv4->protocol != IPPROTO_UDP
		||    udp_dns_reply(&c))
			return XDP_PASS;

		uint32_t swap_ipv4 = ipv4->daddr;
		ipv4->daddr = ipv4->saddr;
		ipv4->saddr = swap_ipv4;

	} else if (eth_proto == __bpf_htons(ETH_P_IPV6)) {
		if (!(ipv6 = parse_ipv6hdr(&c))
		||    ipv6->nexthdr != IPPROTO_UDP
		||    udp_dns_reply(&c))
			return XDP_PASS;

		struct in6_addr swap_ipv6 = ipv6->daddr;
		ipv6->daddr = ipv6->saddr;
		ipv6->saddr = swap_ipv6;
	} else
		return XDP_PASS;

	uint8_t swap_eth[ETH_ALEN];
	memcpy(swap_eth, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, swap_eth, ETH_ALEN);
	return XDP_TX;
}

