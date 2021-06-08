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

#define COOKIE_SECRET 00112233445566778899AABBCCDDEEFF
/* The secret with which to verify the validity of DNS Cookies.
 * Requests with valid DNS Cookies will not be ratelimited.
 */

#define RRL_N_CPUS            2
/* This should be the number of CPUs on your system. Get it by running:
 *
 * 	echo "CPUs: $(grep -c processor /proc/cpuinfo)"
 */

#define RRL_SIZE        1000000
/* This option gives the size of the hashtable. More buckets
 * use more memory, and reduce the chance of hash collisions.
 */

#define RRL_IPv4_PREFIX_LEN  24
/* IPv4 prefix length. Addresses are grouped by netblock.
 */

#define RRL_IPv6_PREFIX_LEN  48
/* IPv6 prefix length. Addresses are grouped by netblock.
 */

#define RRL_RATELIMIT       10 //FIXME setting to 0 breaks because THRESHOLD will be 0
/* The max qps allowed (from one query source). If set to 0 then it is disabled
 * (unlimited rate). Once the rate limit is reached, responses will be dropped.
 * However, one in every RRL_SLIP number of responses is allowed, with the TC
 * bit set. If slip is set to 2, the outgoing response rate will be halved. If
 * it's set to 3, the outgoing response rate will be one-third, and so on.  If
 * you set RRL_SLIP to 10, traffic is reduced to 1/10th.
 */

#define RRL_SLIP              2 //FIXME setting to 0 makes the compiler complain about update_checksum() being unused
/* This option controls the number of packets discarded before we send back a
 * SLIP response (a response with "truncated" bit set to one). 0 disables the
 * sending of SLIP packets, 1 means every query will get a SLIP response.
 * Default is 2, cuts traffic in half and legit users have a fair chance to get
 * a +TC response.
 */

#ifdef  DEBUG
#define DEBUG_PRINTK(...) bpf_printk(__VA_ARGS__)
#else
#define DEBUG_PRINTK(...)
#endif

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
typedef __u8  uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
#define memcpy __builtin_memcpy

#include "siphash4bpf.c"

struct bpf_map_def SEC("maps") jmp_table = {
        .type = BPF_MAP_TYPE_PROG_ARRAY,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(uint32_t),
        .max_entries = 7
};

#define DO_RATE_LIMIT_IPV6 0
#define DO_RATE_LIMIT_IPV4 1
#define COOKIE_VERIFY_IPv6 2
#define COOKIE_VERIFY_IPv4 3
#define STATS_IPv6 4
#define STATS_IPv4 5

struct meta_data {
	uint16_t eth_proto;
	uint16_t ip_pos;
	uint16_t opt_pos;
	uint16_t unused;
};

#define DNS_PORT        53
#define RR_TYPE_OPT     41
#define OPT_CODE_COOKIE 10

#define THRESHOLD ((RRL_RATELIMIT) / (RRL_N_CPUS))
#define FRAME_SIZE   1000000000

#define RRL_MASK_CONCAT1(X)  RRL_MASK ## X
#define RRL_MASK_CONCAT2(X)  RRL_MASK_CONCAT1(X)
#define RRL_IPv4_MASK        RRL_MASK_CONCAT2(RRL_IPv4_PREFIX_LEN)
#define RRL_IPv6_MASK        RRL_MASK_CONCAT2(RRL_IPv6_PREFIX_LEN)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define RRL_MASK1            0x00000080
#define RRL_MASK2            0x000000C0
#define RRL_MASK3            0x000000E0
#define RRL_MASK4            0x000000F0
#define RRL_MASK5            0x000000F8
#define RRL_MASK6            0x000000FC
#define RRL_MASK7            0x000000FE
#define RRL_MASK8            0x000000FF
#define RRL_MASK9            0x000080FF
#define RRL_MASK10           0x0000C0FF
#define RRL_MASK11           0x0000E0FF
#define RRL_MASK12           0x0000F0FF
#define RRL_MASK13           0x0000F8FF
#define RRL_MASK14           0x0000FCFF
#define RRL_MASK15           0x0000FEFF
#define RRL_MASK16           0x0000FFFF
#define RRL_MASK17           0x0080FFFF
#define RRL_MASK18           0x00C0FFFF
#define RRL_MASK19           0x00E0FFFF
#define RRL_MASK20           0x00F0FFFF
#define RRL_MASK21           0x00F8FFFF
#define RRL_MASK22           0x00FCFFFF
#define RRL_MASK23           0x00FEFFFF
#define RRL_MASK24           0x00FFFFFF
#define RRL_MASK25           0x80FFFFFF
#define RRL_MASK26           0xC0FFFFFF
#define RRL_MASK27           0xE0FFFFFF
#define RRL_MASK28           0xF0FFFFFF
#define RRL_MASK29           0xF8FFFFFF
#define RRL_MASK30           0xFCFFFFFF
#define RRL_MASK31           0xFEFFFFFF
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define RRL_MASK1            0x80000000
#define RRL_MASK2            0xC0000000
#define RRL_MASK3            0xE0000000
#define RRL_MASK4            0xF0000000
#define RRL_MASK5            0xF8000000
#define RRL_MASK6            0xFC000000
#define RRL_MASK7            0xFE000000
#define RRL_MASK8            0xFF000000
#define RRL_MASK9            0xFF800000
#define RRL_MASK10           0xFFC00000
#define RRL_MASK11           0xFFE00000
#define RRL_MASK12           0xFFF00000
#define RRL_MASK13           0xFFF80000
#define RRL_MASK14           0xFFFC0000
#define RRL_MASK15           0xFFFE0000
#define RRL_MASK16           0xFFFF0000
#define RRL_MASK17           0xFFFF8000
#define RRL_MASK18           0xFFFFC000
#define RRL_MASK19           0xFFFFE000
#define RRL_MASK20           0xFFFFF000
#define RRL_MASK21           0xFFFFF800
#define RRL_MASK22           0xFFFFFC00
#define RRL_MASK23           0xFFFFFE00
#define RRL_MASK24           0xFFFFFF00
#define RRL_MASK25           0xFFFFFF80
#define RRL_MASK26           0xFFFFFFC0
#define RRL_MASK27           0xFFFFFFE0
#define RRL_MASK28           0xFFFFFFF0
#define RRL_MASK29           0xFFFFFFF8
#define RRL_MASK30           0xFFFFFFFC
#define RRL_MASK31           0xFFFFFFFE
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif
#define RRL_MASK33           RRL_MASK1
#define RRL_MASK34           RRL_MASK2
#define RRL_MASK35           RRL_MASK3
#define RRL_MASK36           RRL_MASK4
#define RRL_MASK37           RRL_MASK5
#define RRL_MASK38           RRL_MASK6
#define RRL_MASK39           RRL_MASK7
#define RRL_MASK40           RRL_MASK8
#define RRL_MASK41           RRL_MASK9
#define RRL_MASK42           RRL_MASK10
#define RRL_MASK43           RRL_MASK11
#define RRL_MASK44           RRL_MASK12
#define RRL_MASK45           RRL_MASK13
#define RRL_MASK46           RRL_MASK14
#define RRL_MASK47           RRL_MASK15
#define RRL_MASK48           RRL_MASK16
#define RRL_MASK49           RRL_MASK17
#define RRL_MASK50           RRL_MASK18
#define RRL_MASK51           RRL_MASK19
#define RRL_MASK52           RRL_MASK20
#define RRL_MASK53           RRL_MASK21
#define RRL_MASK54           RRL_MASK22
#define RRL_MASK55           RRL_MASK23
#define RRL_MASK56           RRL_MASK24
#define RRL_MASK57           RRL_MASK25
#define RRL_MASK58           RRL_MASK26
#define RRL_MASK59           RRL_MASK27
#define RRL_MASK60           RRL_MASK28
#define RRL_MASK61           RRL_MASK29
#define RRL_MASK62           RRL_MASK30
#define RRL_MASK63           RRL_MASK31
#define RRL_MASK65           RRL_MASK1
#define RRL_MASK66           RRL_MASK2
#define RRL_MASK67           RRL_MASK3
#define RRL_MASK68           RRL_MASK4
#define RRL_MASK69           RRL_MASK5
#define RRL_MASK70           RRL_MASK6
#define RRL_MASK71           RRL_MASK7
#define RRL_MASK72           RRL_MASK8
#define RRL_MASK73           RRL_MASK9
#define RRL_MASK74           RRL_MASK10
#define RRL_MASK75           RRL_MASK11
#define RRL_MASK76           RRL_MASK12
#define RRL_MASK77           RRL_MASK13
#define RRL_MASK78           RRL_MASK14
#define RRL_MASK79           RRL_MASK15
#define RRL_MASK80           RRL_MASK16
#define RRL_MASK81           RRL_MASK17
#define RRL_MASK82           RRL_MASK18
#define RRL_MASK83           RRL_MASK19
#define RRL_MASK84           RRL_MASK20
#define RRL_MASK85           RRL_MASK21
#define RRL_MASK86           RRL_MASK22
#define RRL_MASK87           RRL_MASK23
#define RRL_MASK88           RRL_MASK24
#define RRL_MASK89           RRL_MASK25
#define RRL_MASK90           RRL_MASK26
#define RRL_MASK91           RRL_MASK27
#define RRL_MASK92           RRL_MASK28
#define RRL_MASK93           RRL_MASK29
#define RRL_MASK94           RRL_MASK30
#define RRL_MASK95           RRL_MASK31
#define RRL_MASK97           RRL_MASK1
#define RRL_MASK98           RRL_MASK2
#define RRL_MASK99           RRL_MASK3
#define RRL_MASK100          RRL_MASK4
#define RRL_MASK101          RRL_MASK5
#define RRL_MASK102          RRL_MASK6
#define RRL_MASK103          RRL_MASK7
#define RRL_MASK104          RRL_MASK8
#define RRL_MASK105          RRL_MASK9
#define RRL_MASK106          RRL_MASK10
#define RRL_MASK107          RRL_MASK11
#define RRL_MASK108          RRL_MASK12
#define RRL_MASK109          RRL_MASK13
#define RRL_MASK110          RRL_MASK14
#define RRL_MASK111          RRL_MASK15
#define RRL_MASK112          RRL_MASK16
#define RRL_MASK113          RRL_MASK17
#define RRL_MASK114          RRL_MASK18
#define RRL_MASK115          RRL_MASK19
#define RRL_MASK116          RRL_MASK20
#define RRL_MASK117          RRL_MASK21
#define RRL_MASK118          RRL_MASK22
#define RRL_MASK119          RRL_MASK23
#define RRL_MASK120          RRL_MASK24
#define RRL_MASK121          RRL_MASK25
#define RRL_MASK122          RRL_MASK26
#define RRL_MASK123          RRL_MASK27
#define RRL_MASK124          RRL_MASK28
#define RRL_MASK125          RRL_MASK29
#define RRL_MASK126          RRL_MASK30
#define RRL_MASK127          RRL_MASK31

struct bpf_map_def SEC("maps") exclude_v4_prefixes = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct bpf_lpm_trie_key) + sizeof(uint32_t),
	.value_size = sizeof(uint64_t),
	.max_entries = 10000,
	.map_flags = BPF_F_NO_PREALLOC
};

struct bpf_map_def SEC("maps") exclude_v6_prefixes = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct bpf_lpm_trie_key) + 8, // first 64 bits
	.value_size = sizeof(uint64_t),
	.max_entries = 10000,
	.map_flags = BPF_F_NO_PREALLOC
};

/*
 *  Store the time frame
 */
struct bucket {
	uint64_t start_time;
	uint64_t n_packets;
};

struct bpf_map_def SEC("maps") state_map = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(struct bucket),
	.max_entries = RRL_SIZE
};

struct bpf_map_def SEC("maps") state_map_v6 = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(struct in6_addr),
	.value_size = sizeof(struct bucket),
	.max_entries = RRL_SIZE
};


/*
 *  Keep stats
 */
struct stats_qtype {
    uint32_t A;
    uint32_t AAAA;
    uint32_t other;
};
struct stats_qsize {
    uint32_t lt50;
    uint32_t lt75;
    uint32_t lt100;
    uint32_t lt200;
    uint32_t lt500;
    uint32_t lt1000;
    uint32_t gt1000;
};
struct stats {
    struct stats_qtype qtype;
    struct stats_qsize qsize;
};

struct bpf_map_def SEC("maps") stats_v4 = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct bpf_lpm_trie_key) + sizeof(uint32_t),
	.value_size = sizeof(struct stats),
	.max_entries = 10000,
	.map_flags = BPF_F_NO_PREALLOC
};

struct bpf_map_def SEC("maps") stats_v6 = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct bpf_lpm_trie_key) + 8, // first 64 bits
	.value_size = sizeof(struct stats),
	.max_entries = 10000,
	.map_flags = BPF_F_NO_PREALLOC
};

/** Copied from the kernel module of the base03-map-counter example of the
 ** XDP Hands-On Tutorial (see https://github.com/xdp-project/xdp-tutorial )
 *
 * LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

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

        for (i = 0; i < 128; i++) { /* Maximum 128 labels */
                uint8_t o;

                if (c->pos + 1 > c->end)
                        return 0;

                o = *(uint8_t *)c->pos;
                if ((o & 0xC0) == 0xC0) {
                        /* Compression label is last label of dname. */
                        c->pos += 2;
                        return dname;

                } else if (o > 63 || c->pos + o + 1 > c->end)
                        /* Unknown label type */
                        return 0;

                c->pos += o + 1;
                if (!o)
                        return dname;
        }
        return 0;
}

/*
 *  Recalculate the checksum
 */
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

static __always_inline enum xdp_action
do_rate_limit(struct udphdr *udp, struct dnshdr *dns, struct bucket *b)
{
	// increment number of packets
	b->n_packets++;

	// get the current and elapsed time
	uint64_t now = bpf_ktime_get_ns();
	uint64_t elapsed = now - b->start_time;

	// make sure the elapsed time is set and not outside of the frame
	if (b->start_time == 0 || elapsed >= FRAME_SIZE)
	{
		// start new time frame
		b->start_time = now;
		b->n_packets = 0;
	}

	if (b->n_packets < THRESHOLD)
		return XDP_PASS;

#if  RRL_SLIP == 0
	return XDP_DROP;
#else
# if RRL_SLIP >  1
	if (b->n_packets % RRL_SLIP)
		return XDP_DROP;
# endif
	//save the old header values
	uint16_t old_val = dns->flags.as_value;

	// change the DNS flags
	dns->flags.as_bits_and_pieces.ad = 0;
	dns->flags.as_bits_and_pieces.qr = 1;
	dns->flags.as_bits_and_pieces.tc = 1;

	// change the UDP destination to the source
	udp->dest   = udp->source;
	udp->source = __bpf_htons(DNS_PORT);

	// calculate and write the new checksum
	update_checksum(&udp->check, old_val, dns->flags.as_value);

	// bounce
	return XDP_TX;
#endif
}


SEC("xdp-do-rate-limit-ipv6")
int xdp_do_rate_limit_ipv6(struct xdp_md *ctx)
{
	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct ipv6hdr   *ipv6;
	struct in6_addr   ipv6_addr;
	struct udphdr    *udp;
	struct dnshdr    *dns;

	DEBUG_PRINTK("xdp_do_rate_limit_ipv6\n");

	cursor_init(&c, ctx);
	if ((void *)(md + 1) > c.pos || md->ip_pos > 24)
		return XDP_ABORTED;
	c.pos += md->ip_pos;

	if (!(ipv6 = parse_ipv6hdr(&c)) || md->opt_pos > 4096
	||  !(udp = parse_udphdr(&c)) || udp->dest != __bpf_htons(DNS_PORT)
	||  !(dns = parse_dnshdr(&c)))
		return XDP_ABORTED;

	ipv6_addr = ipv6->saddr;
 	// get the rrl bucket from the map by IPv6 address
#if     RRL_IPv6_PREFIX_LEN == 128
#elif   RRL_IPv6_PREFIX_LEN >   96
	ipv6_addr.in6_u.u6_addr32[3] &= RRL_IPv6_MASK;
#else
	ipv6_addr.in6_u.u6_addr32[3] = 0;
# if    RRL_IPv6_PREFIX_LEN ==  96
# elif  RRL_IPv6_PREFIX_LEN >   64
	ipv6_addr.in6_u.u6_addr32[2] &= RRL_IPv6_MASK;
# else
	ipv6_addr.in6_u.u6_addr32[2] = 0;
#  if   RRL_IPv6_PREFIX_LEN ==  64
#  elif RRL_IPv6_PREFIX_LEN >   32
	ipv6_addr.in6_u.u6_addr32[1] &= RRL_IPv6_MASK;
#  else
	ipv6_addr.in6_u.u6_addr32[1] = 0;
#   if  RRL_IPv6_PREFIX_LEN ==   0
	ipv6_addr.in6_u.u6_addr32[0] = 0;
#   elif RRL_IPv6_PREFIX_LEN <  32
	ipv6_addr.in6_u.u6_addr32[0] &= RRL_IPv6_MASK;
#   endif
#  endif
# endif
#endif
 	struct bucket *b = bpf_map_lookup_elem(&state_map_v6, &ipv6_addr);

 	// did we see this IPv6 address before?
	if (b)
		return do_rate_limit(udp, dns, b);

	// create new starting bucket for this key
	struct bucket new_bucket;
	new_bucket.start_time = bpf_ktime_get_ns();
	new_bucket.n_packets = 0;

	// store the bucket and pass the packet
	bpf_map_update_elem(&state_map_v6, &ipv6_addr, &new_bucket, BPF_ANY);
	return XDP_PASS;
}

SEC("xdp-do-rate-limit-ipv4")
int xdp_do_rate_limit_ipv4(struct xdp_md *ctx)
{
	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct iphdr     *ipv4;
	uint32_t          ipv4_addr;
	struct udphdr    *udp;
	struct dnshdr    *dns;

	DEBUG_PRINTK("xdp_do_rate_limit_ipv4\n");

	cursor_init(&c, ctx);
	if ((void *)(md + 1) > c.pos || md->ip_pos > 24)
		return XDP_ABORTED;
	c.pos += md->ip_pos;

	if (!(ipv4 = parse_iphdr(&c)) || md->opt_pos > 4096
	||  !(udp = parse_udphdr(&c)) || udp->dest != __bpf_htons(DNS_PORT)
	||  !(dns = parse_dnshdr(&c)))
		return XDP_ABORTED;

	// get the rrl bucket from the map by IPv4 address
#if   RRL_IPv4_PREFIX_LEN == 32
#elif RRL_IPv4_PREFIX_LEN ==  0
	ipv4_addr = 0;
#else
	ipv4_addr = ipv4->saddr & RRL_IPv4_MASK;
#endif
	struct bucket *b = bpf_map_lookup_elem(&state_map, &ipv4_addr);

	// did we see this IPv4 address before?
	if (b)
		return do_rate_limit(udp, dns, b);

	// create new starting bucket for this key
	struct bucket new_bucket;
	new_bucket.start_time = bpf_ktime_get_ns();
	new_bucket.n_packets = 0;

	// store the bucket and pass the packet
	bpf_map_update_elem(&state_map, &ipv4_addr, &new_bucket, BPF_ANY);
	return XDP_PASS;
}

static __always_inline
int cookie_verify_ipv6(struct cursor *c, struct ipv6hdr *ipv6)
{
	uint8_t  input[32];
	uint64_t hash;

	memcpy(input, c->pos, 16);
	memcpy(input + 16, &ipv6->saddr, 16);
	siphash_ipv6(input, (uint8_t *)&hash);
	return hash == ((uint64_t *)c->pos)[2];
}

SEC("xdp-cookie-verify-ipv6")
int xdp_cookie_verify_ipv6(struct xdp_md *ctx)
{
	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct ipv6hdr   *ipv6;
	struct dns_rr    *opt_rr;
	uint16_t          rdata_len;
	uint8_t           i;

	cursor_init(&c, ctx);
	if ((void *)(md + 1) > c.pos || md->ip_pos > 24)
		return XDP_ABORTED;
	c.pos += md->ip_pos;

	if (!(ipv6 = parse_ipv6hdr(&c)) || md->opt_pos > 4096)
		return XDP_ABORTED;
	c.pos += md->opt_pos;

	if (!(opt_rr = parse_dns_rr(&c))
	||    opt_rr->type != __bpf_htons(RR_TYPE_OPT))
		return XDP_ABORTED;

	rdata_len = __bpf_ntohs(opt_rr->rdata_len);
	for (i = 0; i < 10 && rdata_len >= 28; i++) {
		struct option *opt;
		uint16_t       opt_len;

		if (!(opt = parse_option(&c)))
			return XDP_ABORTED;

		rdata_len -= 4;
		opt_len = __bpf_ntohs(opt->len);
		if (opt->code == __bpf_htons(OPT_CODE_COOKIE)) {
			if (opt_len == 24 && c.pos + 24 <= c.end
			&&  cookie_verify_ipv6(&c, ipv6)) {
				/* Cookie match!
				 * Packet may go staight up to the DNS service
				 */
				DEBUG_PRINTK("IPv6 valid cookie\n");
				return XDP_PASS;
			}
			/* Just a client cookie or a bad cookie
			 * break to go to rate limiting
			 */
			DEBUG_PRINTK("IPv6 bad cookie\n");
			break;
		}
		if (opt_len > 1500 || opt_len > rdata_len
		||  c.pos + opt_len > c.end)
			return XDP_ABORTED;

		rdata_len -= opt_len;
		c.pos += opt_len;
	}
	bpf_tail_call(ctx, &jmp_table, DO_RATE_LIMIT_IPV6);
	return XDP_PASS;
}


static __always_inline
int cookie_verify_ipv4(struct cursor *c, struct iphdr *ipv4)
{
	uint8_t  input[20];
	uint64_t hash;

	memcpy(input, c->pos, 16);
	memcpy(input + 16, &ipv4->saddr, 4);
	siphash_ipv4(input, (uint8_t *)&hash);
	return hash == ((uint64_t *)c->pos)[2];
}

SEC("xdp-cookie-verify-ipv4")
int xdp_cookie_verify_ipv4(struct xdp_md *ctx)
{
	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct iphdr     *ipv4;
	struct dns_rr    *opt_rr;
	uint16_t          rdata_len;
	uint8_t           i;

	cursor_init(&c, ctx);
	if ((void *)(md + 1) > c.pos || md->ip_pos > 24)
		return XDP_ABORTED;
	c.pos += md->ip_pos;

	if (!(ipv4 = parse_iphdr(&c)) || md->opt_pos > 4096)
		return XDP_ABORTED;
	c.pos += md->opt_pos;

	if (!(opt_rr = parse_dns_rr(&c))
	||    opt_rr->type != __bpf_htons(RR_TYPE_OPT))
		return XDP_ABORTED;

	rdata_len = __bpf_ntohs(opt_rr->rdata_len);
	for (i = 0; i < 10 && rdata_len >= 28; i++) {
		struct option *opt;
		uint16_t       opt_len;

		if (!(opt = parse_option(&c)))
			return XDP_ABORTED;

		rdata_len -= 4;
		opt_len = __bpf_ntohs(opt->len);
		if (opt->code == __bpf_htons(OPT_CODE_COOKIE)) {
			if (opt_len == 24 && c.pos + 24 <= c.end
			&&  cookie_verify_ipv4(&c, ipv4)) {
				/* Cookie match!
				 * Packet may go staight up to the DNS service
				 */
				DEBUG_PRINTK("IPv4 valid cookie\n");
				return XDP_PASS;
			}
			/* Just a client cookie or a bad cookie
			 * break to go to rate limiting
			 */
			DEBUG_PRINTK("IPv4 bad cookie\n");
			break;
		}
		if (opt_len > 1500 || opt_len > rdata_len
		||  c.pos + opt_len > c.end)
			return XDP_ABORTED;

		rdata_len -= opt_len;
		c.pos += opt_len;
	}
	//bpf_tail_call(ctx, &jmp_table, DO_RATE_LIMIT_IPV4);
    bpf_tail_call(ctx, &jmp_table, STATS_IPv4);
	return XDP_PASS;
}

static __always_inline
void update_stats(struct udphdr *udp, struct dnshdr *dns, struct dns_qrr *qrr, struct stats *s)
{
    if (qrr->qtype == __bpf_htons(1))
        s->qtype.A++;
    else if (qrr->qtype == __bpf_htons(28))
        s->qtype.AAAA++;
    else {
        DEBUG_PRINTK("unknown qtype %i", __bpf_ntohs(qrr->qtype));
        s->qtype.other++;
    }
    
    uint16_t len = __bpf_ntohs(udp->len);
    DEBUG_PRINTK("len: %i", len);
    if (len < 50)
        s->qsize.lt50++;
    else if (len < 75)
        s->qsize.lt75++;
    else if (len < 100)
        s->qsize.lt100++;
    else if (len < 200)
        s->qsize.lt200++;
    else if (len < 500)
        s->qsize.lt500++;
    else if (len < 1000)
        s->qsize.lt1000++;
    else
        s->qsize.gt1000++;


	DEBUG_PRINTK("in update_stats");
    DEBUG_PRINTK("\t A: %i", s->qtype.A);
	DEBUG_PRINTK("\t AAAA: %i", s->qtype.AAAA);
	DEBUG_PRINTK("\t other: %i", s->qtype.other);
	DEBUG_PRINTK("\t size:");
	DEBUG_PRINTK("\t\t < 50: %i", s->qsize.lt50);
	DEBUG_PRINTK("\t\t < 75: %i", s->qsize.lt75);
	DEBUG_PRINTK("\t\t < 100: %i", s->qsize.lt100);
	DEBUG_PRINTK("\t\t < 200: %i", s->qsize.lt200);
	DEBUG_PRINTK("\t\t < 500: %i", s->qsize.lt500);
	DEBUG_PRINTK("\t\t < 1000: %i", s->qsize.lt1000);
	DEBUG_PRINTK("\t\t => 1000: %i", s->qsize.gt1000);

	//DEBUG_PRINTK("\nlen: %i", __bpf_ntohs(udp->len));
}

SEC("xdp-stats-ipv6")
int xdp_stats_ipv6(struct xdp_md *ctx)
{
    return 1;
}

SEC("xdp-stats-ipv4")
int xdp_stats_ipv4(struct xdp_md *ctx)
{
	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct iphdr     *ipv4;
	uint32_t          ipv4_addr;
	struct udphdr    *udp;
	struct dnshdr    *dns;
	struct dns_qrr    *qrr;
	cursor_init(&c, ctx);

	if ((void *)(md + 1) > c.pos || md->ip_pos > 24)
		return XDP_ABORTED;
	c.pos += md->ip_pos;

	if (!(ipv4 = parse_iphdr(&c)) || md->opt_pos > 4096
	||  !(udp = parse_udphdr(&c)) || udp->dest != __bpf_htons(DNS_PORT)
	||  !(dns = parse_dnshdr(&c))
	||  !skip_dname(&c)
	||  !(qrr = parse_dns_qrr(&c)))
		return XDP_ABORTED;

#if   RRL_IPv4_PREFIX_LEN == 32
#elif RRL_IPv4_PREFIX_LEN ==  0
	ipv4_addr = 0;
#else
	ipv4_addr = ipv4->saddr & RRL_IPv4_MASK;
#endif
    // search for the prefix in the LPM trie
    struct {
        uint32_t prefixlen;
        uint32_t ipv4_addr;
    } key4 = {
        .prefixlen = 32,
        .ipv4_addr = ipv4->saddr
    };
    struct stats *s = bpf_map_lookup_elem(&stats_v4, &key4);
    if (!s) {
        struct stats new_stats = {{0,0,0}, {0,0,0,0}};
        s = &new_stats;
        DEBUG_PRINTK("new stats: %i", new_stats.qtype.A);
        DEBUG_PRINTK("new stats: %i", s->qtype.A);
	    bpf_map_update_elem(&stats_v4, &key4, &new_stats, BPF_ANY);
    } else {
        DEBUG_PRINTK("existing stats: %i", s->qtype.A);
    }

    update_stats(udp, dns, qrr, s);

	bpf_tail_call(ctx, &jmp_table, DO_RATE_LIMIT_IPV4);
    return XDP_PASS;
}


SEC("xdp-dns-cookies")
int xdp_dns_cookies(struct xdp_md *ctx)
{
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct cursor     c;
	struct ethhdr    *eth;
	struct ipv6hdr   *ipv6;
	struct iphdr     *ipv4;
	struct udphdr    *udp;
	struct dnshdr    *dns;
	uint64_t         *count;

	if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct meta_data)))
		return XDP_PASS;

	cursor_init(&c, ctx);
	md = (void *)(long)ctx->data_meta;
	if ((void *)(md + 1) > c.pos)
		return XDP_PASS;

	if (!(eth = parse_eth(&c, &md->eth_proto)))
		return XDP_PASS;
	md->ip_pos = c.pos - (void *)eth;

	if (md->eth_proto == __bpf_htons(ETH_P_IPV6)) {
		if (!(ipv6 = parse_ipv6hdr(&c))
		||  !(ipv6->nexthdr == IPPROTO_UDP)
	 	||  !(udp = parse_udphdr(&c))
		||  !(udp->dest == __bpf_htons(DNS_PORT))
	 	||  !(dns = parse_dnshdr(&c)))
	 		return XDP_PASS; /* Not DNS */

		// search for the prefix in the LPM trie
		struct {
			uint32_t        prefixlen;
			struct in6_addr ipv6_addr;
		} key6 = {
			.prefixlen = 64,
			.ipv6_addr = ipv6->daddr
		};
		// if the prefix matches, we exclude it from rate limiting
		if ((count=bpf_map_lookup_elem(&exclude_v6_prefixes, &key6))) {
			lock_xadd(count, 1);
			return XDP_PASS;
		}
		if (dns->flags.as_bits_and_pieces.qr
		||  dns->qdcount != __bpf_htons(1)
		||  dns->ancount || dns->nscount
		||  dns->arcount >  __bpf_htons(2)
		||  !skip_dname(&c)
		||  !parse_dns_qrr(&c))
			return XDP_ABORTED; // Return FORMERR?

		if (dns->arcount == 0) {
			bpf_tail_call(ctx, &jmp_table, DO_RATE_LIMIT_IPV6);
			return XDP_PASS;
		}
		if (c.pos + 1 > c.end
		||  *(uint8_t *)c.pos != 0)
			return XDP_ABORTED; // Return FORMERR?

		md->opt_pos = c.pos + 1 - (void *)(ipv6 + 1);
		bpf_tail_call(ctx, &jmp_table, COOKIE_VERIFY_IPv6);
		
	} else if (md->eth_proto == __bpf_htons(ETH_P_IP)) {
		if (!(ipv4 = parse_iphdr(&c))
		||  !(ipv4->protocol == IPPROTO_UDP)
	 	||  !(udp = parse_udphdr(&c))
		||  !(udp->dest == __bpf_htons(DNS_PORT))
	 	||  !(dns = parse_dnshdr(&c)))
	 		return XDP_PASS; /* Not DNS */
	 		
		// search for the prefix in the LPM trie
		struct {
			uint32_t prefixlen;
			uint32_t ipv4_addr;
		} key4 = {
			.prefixlen = 32,
			.ipv4_addr = ipv4->saddr
		};

		// if the prefix matches, we exclude it from rate limiting
		if ((count=bpf_map_lookup_elem(&exclude_v4_prefixes, &key4))) {
			lock_xadd(count, 1);
			return XDP_PASS;
		}

		if (dns->flags.as_bits_and_pieces.qr
		||  dns->qdcount != __bpf_htons(1)
		||  dns->ancount || dns->nscount
		||  dns->arcount >  __bpf_htons(2)
		||  !skip_dname(&c)
		||  !parse_dns_qrr(&c))
			return XDP_ABORTED; // return FORMERR?

		if (dns->arcount == 0) {
			bpf_tail_call(ctx, &jmp_table, DO_RATE_LIMIT_IPV4);
			return XDP_PASS;
		}
		if (c.pos + 1 > c.end
		||  *(uint8_t *)c.pos != 0)
			return XDP_ABORTED; // Return FORMERR?

		md->opt_pos = c.pos + 1 - (void *)(ipv4 + 1);
		bpf_tail_call(ctx, &jmp_table, COOKIE_VERIFY_IPv4);
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

