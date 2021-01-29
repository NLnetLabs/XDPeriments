/*
 * DNS Response Rate Limiting module in XDP.
 *
 * October 2020 - Tom Carpay & Willem Toorop
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

#define RRL_RATELIMIT       200
/* The max qps allowed (from one query source). If set to 0 then it is disabled
 * (unlimited rate). Once the rate limit is reached, responses will be dropped.
 * However, one in every RRL_SLIP number of responses is allowed, with the TC
 * bit set. If slip is set to 2, the outgoing response rate will be halved. If
 * it's set to 3, the outgoing response rate will be one-third, and so on.  If
 * you set RRL_SLIP to 10, traffic is reduced to 1/10th.
 */

#define RRL_SLIP              2
/* This option controls the number of packets discarded before we send back a
 * SLIP response (a response with "truncated" bit set to one). 0 disables the
 * sending of SLIP packets, 1 means every query will get a SLIP response.
 * Default is 2, cuts traffic in half and legit users have a fair chance to get
 * a +TC response.
 */



#include <linux/bpf.h>
#include <linux/if_ether.h> /* for struct ethhdr   */
#include <linux/ip.h>       /* for struct iphdr    */
#include <linux/ipv6.h>     /* for struct ipv6hdr  */
#include <linux/in.h>       /* for IPPROTO_UDP     */
#include <linux/udp.h>      /* for struct udphdr   */
#include <bpf_helpers.h>    /* for bpf_get_prandom_u32() */
#include <bpf_endian.h>     /* for __bpf_htons()   */

// do not use libc includes because this causes clang
// to include 32bit headers on 64bit ( only ) systems.
typedef __u8  uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
#define memcpy __builtin_memcpy

#define DNS_PORT             53

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
	.max_entries = 10000
};

struct bpf_map_def SEC("maps") exclude_v6_prefixes = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct bpf_lpm_trie_key) + 8, // first 64 bits
	.value_size = sizeof(uint64_t),
	.max_entries = 10000
};

#if RRL_RATELIMIT == 0
SEC("xdp-rrl")
int xdp_rrl(struct xdp_md *ctx)
{
	(void)ctx;
	return XDP_PASS;
}
#else

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

/*
 *  Helper pointer to parse the incoming packets
 */
struct cursor {
	void *pos;
	void *end;
};


/*
 *  Initializer of a cursor pointer
 */
static __always_inline
void cursor_init(struct cursor *c, struct xdp_md *ctx)
{
	c->end = (void *)(long)ctx->data_end;
	c->pos = (void *)(long)ctx->data;
}

#define PARSE_FUNC_DECLARATION(STRUCT)			\
static __always_inline						\
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

/*
 * Parse ethernet frame and fill the struct
 */
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
	//bpf_printk("bounce\n");
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

static __always_inline enum xdp_action
udp_dns_reply_v4(struct cursor *c, uint32_t key)
{
	struct udphdr  *udp;
	struct dnshdr  *dns;

	// check that we have a DNS packet
	if (!(udp = parse_udphdr(c)) || udp->dest != __bpf_htons(DNS_PORT)
	||  !(dns = parse_dnshdr(c)))
		return XDP_PASS;

	// search for the prefix in the LPM trie
	struct {
		uint32_t prefixlen;
		uint32_t ipv4_addr;
	} key4 = {
		.prefixlen = 32,
		.ipv4_addr = key
	};
	uint64_t *count = bpf_map_lookup_elem(&exclude_v4_prefixes, &key4);

	// if the prefix matches, we exclude it from rate limiting
	if (count) {
		lock_xadd(count, 1);
		return XDP_PASS;
	}

	// get the rrl bucket from the map by IPv4 address
#if   RRL_IPv4_PREFIX_LEN == 32
#elif RRL_IPv4_PREFIX_LEN ==  0
	key =  0;
#else
	key &= RRL_IPv4_MASK;
#endif
	struct bucket *b = bpf_map_lookup_elem(&state_map, &key);

	// did we see this IPv4 address before?
	if (b)
		return do_rate_limit(udp, dns, b);

	// create new starting bucket for this key
	struct bucket new_bucket;
	new_bucket.start_time = bpf_ktime_get_ns();
	new_bucket.n_packets = 0;

	// store the bucket and pass the packet
	bpf_map_update_elem(&state_map, &key, &new_bucket, BPF_ANY);
	return XDP_PASS;
}

static __always_inline enum xdp_action
udp_dns_reply_v6(struct cursor *c, struct in6_addr *key)
{
 	struct udphdr  *udp;
 	struct dnshdr  *dns;

 	// check that we have a DNS packet
 	if (!(udp = parse_udphdr(c)) || udp->dest != __bpf_htons(DNS_PORT)
 	||  !(dns = parse_dnshdr(c)))
 		return XDP_PASS;

	// search for the prefix in the LPM trie
	struct {
		uint32_t        prefixlen;
		struct in6_addr ipv6_addr;
	} key6 = {
		.prefixlen = 64,
		.ipv6_addr = *key
	};
	uint64_t *count = bpf_map_lookup_elem(&exclude_v6_prefixes, &key6);

	// if the prefix is matches, we exclude it from rate limiting
	if (count) {
		lock_xadd(count, 1);
		return XDP_PASS;
	}
 	// get the rrl bucket from the map by IPv6 address
#if     RRL_IPv6_PREFIX_LEN == 128
#elif   RRL_IPv6_PREFIX_LEN >   96
	key6.ipv6_addr.in6_u.u6_addr32[3] &= RRL_IPv6_MASK;
#else
	key6.ipv6_addr.in6_u.u6_addr32[3] = 0;
# if    RRL_IPv6_PREFIX_LEN ==  96
# elif  RRL_IPv6_PREFIX_LEN >   64
	key6.ipv6_addr.in6_u.u6_addr32[2] &= RRL_IPv6_MASK;
# else
	key6.ipv6_addr.in6_u.u6_addr32[2] = 0;
#  if   RRL_IPv6_PREFIX_LEN ==  64
#  elif RRL_IPv6_PREFIX_LEN >   32
	key6.ipv6_addr.in6_u.u6_addr32[1] &= RRL_IPv6_MASK;
#  else
	key6.ipv6_addr.in6_u.u6_addr32[1] = 0;
#   if  RRL_IPv6_PREFIX_LEN ==   0
	key6.ipv6_addr.in6_u.u6_addr32[0] = 0;
#   elif RRL_IPv6_PREFIX_LEN <  32
	key6.ipv6_addr.in6_u.u6_addr32[0] &= RRL_IPv6_MASK;
#   endif
#  endif
# endif
#endif
 	struct bucket *b = bpf_map_lookup_elem(&state_map_v6, &key6.ipv6_addr);

 	// did we see this IPv6 address before?
	if (b)
		return do_rate_limit(udp, dns, b);

	// create new starting bucket for this key
	struct bucket new_bucket;
	new_bucket.start_time = bpf_ktime_get_ns();
	new_bucket.n_packets = 0;

	// store the bucket and pass the packet
	bpf_map_update_elem(&state_map_v6, &key6.ipv6_addr, &new_bucket, BPF_ANY);
	return XDP_PASS;
}


SEC("xdp-rrl")
int xdp_rrl(struct xdp_md *ctx)
{
	struct cursor   c;
	struct ethhdr  *eth;
	uint16_t        eth_proto;
	struct iphdr   *ipv4;
	struct ipv6hdr *ipv6;
	enum xdp_action r = XDP_PASS;

	cursor_init(&c, ctx);
	if (!(eth = parse_eth(&c, &eth_proto)))
		return XDP_PASS;

	if (eth_proto == __bpf_htons(ETH_P_IP)) {
		if (!(ipv4 = parse_iphdr(&c))
		||    ipv4->protocol != IPPROTO_UDP
		||   (r = udp_dns_reply_v4(&c, ipv4->saddr)) != XDP_TX)
			return r;

		uint32_t swap_ipv4 = ipv4->daddr;
		ipv4->daddr = ipv4->saddr;
		ipv4->saddr = swap_ipv4;

	} else if (eth_proto == __bpf_htons(ETH_P_IPV6)) {
		if (!(ipv6 = parse_ipv6hdr(&c))
		||    ipv6->nexthdr  != IPPROTO_UDP
		||   (r = udp_dns_reply_v6(&c, &ipv6->saddr)) != XDP_TX)
			return r;

		struct in6_addr swap_ipv6 = ipv6->daddr;
		ipv6->daddr = ipv6->saddr;
		ipv6->saddr = swap_ipv6;
	} else
		return XDP_PASS;

	uint8_t swap_eth[ETH_ALEN];
	memcpy(swap_eth, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, swap_eth, ETH_ALEN);

	// bounce the request
	return XDP_TX;
}
#endif /* #if RRL_RATELIMIT == 0 */

char __license[] SEC("license") = "GPL";
