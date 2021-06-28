#include <linux/pkt_cls.h>    /* for TC_ACT_OK*/
#include <iproute2/bpf_elf.h> /* for struct bpf_elf_map */
#include <linux/bpf.h>        /* of bpf_helpers.h */
#include <bpf_helpers.h>      /* for SEC */
#include "bpf-dns.h"
#include "tc_stats.h"
#include "murmur3.c"

#define BLOOM_THRESHOLD 10  // minimum observations before adding to dnames map
#define DIAG_BLOOMCOUNT 0   // number of elements tracked by the bloom filter
#define DIAG_HIT 1          // number of hits / successful lookups
#define DIAG_OVERFLOW 2     // track overflows of the bloom uint8_t

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
	}

	uint32_t size_key = __bpf_ntohs(udp->len);
	uint64_t* current_size_count = bpf_map_lookup_elem(response_sizes, &size_key);
	if (current_size_count) {
		*current_size_count += 1;
	}

    return 0;
}

#define COPY_DNAME(skb, offset, dst, dname_len, n) {\
    if (dname_len >= n) {\
        bpf_skb_load_bytes(skb, offset, dst, n);\
        offset += n;\
        dst += n;\
        dname_len -= n;\
    }\
}

#define COPY_TLD(skb, offset, dst, tld_len, n) {\
    if (tld_len == n) {\
        bpf_skb_load_bytes(skb, offset - tld_len + 1, res->tld, n - 1);\
    }\
}

// returns length of dname
// records the dname, length and tld offset in dname* res
static __always_inline
int parse_dname(struct dname *res, struct cursor *c, struct __sk_buff *skb)
{
    uint32_t offset = (uint32_t)(c->pos - (void *)(long)skb->data);

    res->len = 0;
    uint8_t tld_offset = 0;


    // determine total length of the dname, and the offset of the last label
    uint8_t i;
    for (i = 0; i < 128; i++) {
        if (c->pos + 1 > c->end) {
            return res->len;
        }

        uint8_t labellen;
        labellen = *(uint8_t*)c->pos;
        if (labellen == 0)
            break;

        tld_offset = res->len;

        if (c->pos + labellen + 1 > c->end) {
            return res->len;
        }
        res->len += labellen + 1;
        c->pos += labellen + 1;
    }

    // copy the dname in chunks of 64/32/16 etc bytes

    void* to= res->full;
    uint32_t dname_len = res->len;

    COPY_DNAME(skb, offset, to, dname_len, 64);
    COPY_DNAME(skb, offset, to, dname_len, 32);
    COPY_DNAME(skb, offset, to, dname_len, 16);
    COPY_DNAME(skb, offset, to, dname_len, 8);
    COPY_DNAME(skb, offset, to, dname_len, 4);
    COPY_DNAME(skb, offset, to, dname_len, 2);
    COPY_DNAME(skb, offset, to, dname_len, 1);


    // now copy the .tld
    int tld_len = res->len - tld_offset;

    if (tld_len > 10) {
        bpf_skb_load_bytes(skb, offset - tld_len + 1, res->tld, 10);
    }

    // TODO make this an if-else instead of separate if's
    COPY_TLD(skb, offset, res->tld, tld_len, 10); 
    COPY_TLD(skb, offset, res->tld, tld_len, 9); 
    COPY_TLD(skb, offset, res->tld, tld_len, 8); 
    COPY_TLD(skb, offset, res->tld, tld_len, 7); 
    COPY_TLD(skb, offset, res->tld, tld_len, 6); 
    COPY_TLD(skb, offset, res->tld, tld_len, 5); 
    COPY_TLD(skb, offset, res->tld, tld_len, 4); 
    COPY_TLD(skb, offset, res->tld, tld_len, 3); 
    
    return res->len;
}

static __always_inline
int update_dnames(struct bpf_elf_map* dnames, struct cursor* c, struct __sk_buff* skb)
{
        struct dname dname = {0};
        size_t len = parse_dname(&dname, c, skb);

        // update TLDs map
		uint64_t *tld_p = bpf_map_lookup_elem(&tlds, dname.tld);
        if (tld_p) {
            *tld_p += 1;
            //bpf_printk("existing TLD %s, now seen %i", dname.tld, *tld_p);
        } else {
            //bpf_printk("new TLD %s, inserting ..", dname.tld);
            uint64_t one = 1;
            if (bpf_map_update_elem(&tlds, dname.tld, &one, 0) < 0) {
                bpf_printk("failed to insert new TLD");
            }
        }


	// Calculate hashes for the bloom filter
	uint32_t seed = 0;
	len = 255; // FIXME using the actual dname.len does not work, for some reason
	uint32_t h1 = murmur3_32((uint8_t *)dname.full, len, seed) % (1 << 27);
	seed = 0x12345;
	uint32_t h2 = murmur3_32((uint8_t *)dname.full, len, seed) % (1 << 27);
	//Kirsch-Mitzenmacher-Optimization: hash_i = hash1 + i x hash2
	uint32_t h3 = (h1 + 3 * h2) % (1 << 27);
	uint32_t h4 = (h1 + 4 * h2) % (1 << 27);
	uint32_t h5 = (h1 + 5 * h2) % (1 << 27);
	uint32_t h6 = (h1 + 6 * h2) % (1 << 27);
	//bpf_printk("hashes: %x %x %x", h1, h2, h3);
	//bpf_printk("        %x %x %x", h4, h5, h6);

	uint8_t *r1 = bpf_map_lookup_elem(&dnames_bloom, &h1);
	uint8_t *r2 = bpf_map_lookup_elem(&dnames_bloom, &h2);
	uint8_t *r3 = bpf_map_lookup_elem(&dnames_bloom, &h3);
	uint8_t *r4 = bpf_map_lookup_elem(&dnames_bloom, &h4);
	uint8_t *r5 = bpf_map_lookup_elem(&dnames_bloom, &h5);
	uint8_t *r6 = bpf_map_lookup_elem(&dnames_bloom, &h6);
	if (r1 && r2 && r3 && r4 && r5 && r6) { // always true because we're working with a _ARRAY
		if (*r1 >= BLOOM_THRESHOLD &&
            *r2 >= BLOOM_THRESHOLD &&
            *r3 >= BLOOM_THRESHOLD &&
            *r4 >= BLOOM_THRESHOLD &&
            *r5 >= BLOOM_THRESHOLD &&
            *r6 >= BLOOM_THRESHOLD
            ) {

            //bpf_printk("dname %s seen before according to bloom filter", dname.full);
            
            // dname seen before according to bloom filter
            // update the dnames map:
            uint64_t *dnamep = bpf_map_lookup_elem(dnames, dname.full);
            if (dnamep) {
                *dnamep += 1;
            } else {
                uint64_t new_value = BLOOM_THRESHOLD + 1;
                if (bpf_map_update_elem(dnames, dname.full, &new_value, 0) < 0) {
                    bpf_printk("Failed to insert dname %s", dname.full);
                }
            }

			//update diagnostics
            uint32_t diag_index = DIAG_HIT;
			uint64_t *bloomcount = bpf_map_lookup_elem(&diagnostics, &diag_index);
			if (bloomcount) {
				*bloomcount += 1;
            }
		} else {

            // not enough observations to pass the threshold yet,
            // update the counting bloom filter
            
            // Before increasing the counting bloom filter, check whether this
            // is the first occurrence and we thus need to increase the bloom
            // filter element count in the diagnostics
            uint32_t diag_index = DIAG_BLOOMCOUNT;
			uint64_t *bloomcount = bpf_map_lookup_elem(&diagnostics, &diag_index);
			if (bloomcount) { // satisfy the verifier
                if (*r1 == 0 ||
                    *r2 == 0 ||
                    *r3 == 0 ||
                    *r4 == 0 ||
                    *r5 == 0 ||
                    *r6 == 0)
				*bloomcount += 1;
            }

            // Now, increase the right counters in the bloom filter, while
            // checking for (and keep track of) overflows
            
            diag_index = DIAG_OVERFLOW;
			uint64_t *overflowcount = bpf_map_lookup_elem(&diagnostics, &diag_index);
            if (overflowcount) {
                if (*r1 == 255)  *overflowcount += 1; else *r1 += 1;
                if (*r2 == 255)  *overflowcount += 1; else *r2 += 1;
                if (*r3 == 255)  *overflowcount += 1; else *r3 += 1;
                if (*r4 == 255)  *overflowcount += 1; else *r4 += 1;
                if (*r5 == 255)  *overflowcount += 1; else *r5 += 1;
                if (*r6 == 255)  *overflowcount += 1; else *r6 += 1;
            }
		}
	}

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
        //update_dnames(&dnames_v6, &c, skb);
        update_dnames(&dnames, &c, skb);

	} else if (eth_proto == __bpf_htons(ETH_P_IP)) {
        if (!(ipv4 = parse_iphdr(&c))
        ||  !(ipv4->protocol == IPPROTO_UDP)
        ||  !(udp = parse_udphdr(&c))
        ||  !(udp->source == __bpf_htons(DNS_PORT))
        ||  !(dns = parse_dnshdr(&c)))
            return TC_ACT_OK; /* Not DNS */

		//bpf_printk("IPv4 DNS response\n");
		update_stats(&rcodes_v4, &response_sizes_v4, udp, dns);
        //update_dnames(&dnames_v4, &c, skb);
        update_dnames(&dnames, &c, skb);
	}
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
