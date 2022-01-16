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
#ifndef _BPF_DNS_H
#define _BPF_DNS_H

#include <linux/bpf.h>
#include <linux/if_ether.h> /* for struct ethhdr   */
#include <linux/ip.h>       /* for struct iphdr    */
#include <linux/ipv6.h>     /* for struct ipv6hdr  */
#include <linux/in.h>       /* for IPPROTO_UDP     */
#include <linux/udp.h>      /* for struct udphdr   */
#include <bpf_endian.h>     /* for __bpf_htons()   */

/* do not use libc includes because this causes clang
 * to include 32bit headers on 64bit ( only ) systems.
 */
typedef __u8  uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
#define memcpy __builtin_memcpy

#define DNS_PORT         53
#define RR_TYPE_OPT      41
#define OPT_CODE_PADDING 12

/*
 *  Store the VLAN header
 */
struct vlanhdr {
	uint16_t tci;
	uint16_t encap_proto;
};

/*
 *  Store the DNS header
 */
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

struct option {
	uint16_t code;
	uint16_t len;
	uint8_t  data[];
} __attribute__((packed));


/*
 *  Helper pointer to parse the incoming packets
 */
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

static __always_inline
void cursor_init_skb(struct cursor *c, struct __sk_buff *skb)
{
        c->end = (void *)(long)skb->data_end;
        c->pos = (void *)(long)skb->data;
}

#define PARSE_FUNC_DECLARATION(STRUCT)			\
static __always_inline \
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
PARSE_FUNC_DECLARATION(option)

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

static  inline
uint8_t *skip_dname(struct cursor *c)
{
        uint8_t *dname = c->pos;
	uint8_t i;

        for (i = 0; i < 127; i++) { /* Maximum 127 labels */
                uint8_t o;

                if (c->pos + 1 > c->end)
                        return 0;

                o = *(uint8_t *)c->pos;
                if ((o & 0xC0) == 0xC0) {
                        /* Compression label is last label of dname. */
                        c->pos += 2;
			return dname;

                } else if (o > 63 || c->pos + o + 1 > c->end)
			return 0;

                c->pos += o + 1;
                if (!o)
                        return dname;
        }
        return 0;
}

#endif
