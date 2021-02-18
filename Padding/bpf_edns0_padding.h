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
#ifndef _BPF_EDNS0_PADDING_H
#define _BPF_EDNS0_PADDING_H

#include <iproute2/bpf_elf.h> /* for struct bpf_elf_map */
#include <linux/bpf.h>        /* of bpf_helpers.h */
#include <bpf_helpers.h>      /* for SEC */
#include "bpf-dns.h"

struct query_v6 {
	struct in6_addr addr;
	uint16_t        port;
	uint16_t        id;
};

struct bpf_elf_map SEC("maps") queries_v6 = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.size_key = sizeof(struct query_v6),
	.size_value = sizeof(uint8_t),
	.max_elem = 10000,
	.pinning = PIN_GLOBAL_NS
};

struct query_v4 {
	uint32_t addr;
	uint16_t port;
	uint16_t id;
};

struct bpf_elf_map SEC("maps") queries_v4 = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.size_key = sizeof(struct query_v4),
	.size_value = sizeof(uint8_t),
	.max_elem = 10000,
	.pinning = PIN_GLOBAL_NS
};

#endif
