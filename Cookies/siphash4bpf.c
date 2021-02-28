/*
   SipHash reference C implementation

   Copyright (c) 2012-2016 Jean-Philippe Aumasson
   <jeanphilippe.aumasson@gmail.com>
   Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along
   with
   this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

/* default: SipHash-2-4 */
#define cROUNDS 2
#define dROUNDS 4

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define U32TO8_LE(p, v)                                                        \
    (p)[0] = (uint8_t)((v));                                                   \
    (p)[1] = (uint8_t)((v) >> 8);                                              \
    (p)[2] = (uint8_t)((v) >> 16);                                             \
    (p)[3] = (uint8_t)((v) >> 24);

#define U64TO8_LE(p, v)                                                        \
    U32TO8_LE((p), (uint32_t)((v)));                                           \
    U32TO8_LE((p) + 4, (uint32_t)((v) >> 32));

#define U8TO64_LE(p)                                                           \
    (((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8) |                        \
     ((uint64_t)((p)[2]) << 16) | ((uint64_t)((p)[3]) << 24) |                 \
     ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40) |                 \
     ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56))

#define SIPROUND                                                               \
    do {                                                                       \
        v0 += v1;                                                              \
        v1 = ROTL(v1, 13);                                                     \
        v1 ^= v0;                                                              \
        v0 = ROTL(v0, 32);                                                     \
        v2 += v3;                                                              \
        v3 = ROTL(v3, 16);                                                     \
        v3 ^= v2;                                                              \
        v0 += v3;                                                              \
        v3 = ROTL(v3, 21);                                                     \
        v3 ^= v0;                                                              \
        v2 += v1;                                                              \
        v1 = ROTL(v1, 17);                                                     \
        v1 ^= v2;                                                              \
        v2 = ROTL(v2, 32);                                                     \
    } while (0)

#ifdef DEBUG
#define TRACE                                                           \
        bpf_printk("v0 %x %x\n", (v0 >> 32), (uint32_t)v0); \
        bpf_printk("v1 %x %x\n", (v1 >> 32), (uint32_t)v1); \
        bpf_printk("v2 %x %x\n", (v2 >> 32), (uint32_t)v2); \
        bpf_printk("v3 %x %x\n", (v3 >> 32), (uint32_t)v3);
#else
#define TRACE
#endif

#define STRINGIFY_HELPER(A) #A
#define STRINGIFY(...) STRINGIFY_HELPER(__VA_ARGS__)
#define COOKIE_SECRET_STR ((const char *)STRINGIFY(COOKIE_SECRET))

#define HEXTONIBBLE(c) (*(c) >= 'A' ? (*(c) - 'A')+10 : (*(c)-'0'))
#define HEXTOBYTE(c) (HEXTONIBBLE(c)*16 + HEXTONIBBLE(c+1))

#define COOKIE_SECRET_K0 \
    ( ((uint64_t)HEXTOBYTE(COOKIE_SECRET_STR+ 0) <<  0) \
    | ((uint64_t)HEXTOBYTE(COOKIE_SECRET_STR+ 2) <<  8) \
    | ((uint64_t)HEXTOBYTE(COOKIE_SECRET_STR+ 4) << 16) \
    | ((uint64_t)HEXTOBYTE(COOKIE_SECRET_STR+ 6) << 24) \
    | ((uint64_t)HEXTOBYTE(COOKIE_SECRET_STR+ 8) << 32) \
    | ((uint64_t)HEXTOBYTE(COOKIE_SECRET_STR+10) << 40) \
    | ((uint64_t)HEXTOBYTE(COOKIE_SECRET_STR+12) << 48) \
    | ((uint64_t)HEXTOBYTE(COOKIE_SECRET_STR+14) << 56))

#define COOKIE_SECRET_K1 \
    ( ((uint64_t)HEXTOBYTE(COOKIE_SECRET_STR+16) <<  0) \
    | ((uint64_t)HEXTOBYTE(COOKIE_SECRET_STR+18) <<  8) \
    | ((uint64_t)HEXTOBYTE(COOKIE_SECRET_STR+20) << 16) \
    | ((uint64_t)HEXTOBYTE(COOKIE_SECRET_STR+22) << 24) \
    | ((uint64_t)HEXTOBYTE(COOKIE_SECRET_STR+24) << 32) \
    | ((uint64_t)HEXTOBYTE(COOKIE_SECRET_STR+26) << 40) \
    | ((uint64_t)HEXTOBYTE(COOKIE_SECRET_STR+28) << 48) \
    | ((uint64_t)HEXTOBYTE(COOKIE_SECRET_STR+30) << 56))

#define INLENv4 20
#define INLENv6 32
#define OUTLEN   8
static inline void siphash_ipv4(const uint8_t *in, uint8_t *out)
{
    uint64_t v0 = 0x736f6d6570736575ULL ^ COOKIE_SECRET_K0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ COOKIE_SECRET_K1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ COOKIE_SECRET_K0;
    uint64_t v3 = 0x7465646279746573ULL ^ COOKIE_SECRET_K1;
    uint64_t m;
    int i;
    const uint8_t *end = in + INLENv4 - (INLENv4 % sizeof(uint64_t));
    const int left = INLENv4 & 7;
    uint64_t b = ((uint64_t)INLENv4) << 56;
    if (OUTLEN == 16)
        v1 ^= 0xee;

    for (; in != end; in += 8) {
        m = U8TO64_LE(in);
        v3 ^= m;

        TRACE;
        for (i = 0; i < cROUNDS; ++i)
            SIPROUND;

        v0 ^= m;
    }

    switch (left) {
    case 7:
        b |= ((uint64_t)in[6]) << 48;
    case 6:
        b |= ((uint64_t)in[5]) << 40;
    case 5:
        b |= ((uint64_t)in[4]) << 32;
    case 4:
        b |= ((uint64_t)in[3]) << 24;
    case 3:
        b |= ((uint64_t)in[2]) << 16;
    case 2:
        b |= ((uint64_t)in[1]) << 8;
    case 1:
        b |= ((uint64_t)in[0]);
        break;
    case 0:
        break;
    }

    v3 ^= b;

    TRACE;
    for (i = 0; i < cROUNDS; ++i)
        SIPROUND;

    v0 ^= b;

    if (OUTLEN == 16)
        v2 ^= 0xee;
    else
        v2 ^= 0xff;

    TRACE;
    for (i = 0; i < dROUNDS; ++i)
        SIPROUND;

    b = v0 ^ v1 ^ v2 ^ v3;
    U64TO8_LE(out, b);
}

static inline void siphash_ipv6(const uint8_t *in, uint8_t *out)
{
    uint64_t v0 = 0x736f6d6570736575ULL ^ COOKIE_SECRET_K0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ COOKIE_SECRET_K1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ COOKIE_SECRET_K0;
    uint64_t v3 = 0x7465646279746573ULL ^ COOKIE_SECRET_K1;
    uint64_t m;
    int i;
    const uint8_t *end = in + INLENv6 - (INLENv6 % sizeof(uint64_t));
    const int left = INLENv6 & 7;
    uint64_t b = ((uint64_t)INLENv6) << 56;
    if (OUTLEN == 16)
        v1 ^= 0xee;

    for (; in != end; in += 8) {
        m = U8TO64_LE(in);
        v3 ^= m;

        TRACE;
        for (i = 0; i < cROUNDS; ++i)
            SIPROUND;

        v0 ^= m;
    }

    switch (left) {
    case 7:
        b |= ((uint64_t)in[6]) << 48;
    case 6:
        b |= ((uint64_t)in[5]) << 40;
    case 5:
        b |= ((uint64_t)in[4]) << 32;
    case 4:
        b |= ((uint64_t)in[3]) << 24;
    case 3:
        b |= ((uint64_t)in[2]) << 16;
    case 2:
        b |= ((uint64_t)in[1]) << 8;
    case 1:
        b |= ((uint64_t)in[0]);
        break;
    case 0:
        break;
    }

    v3 ^= b;

    TRACE;
    for (i = 0; i < cROUNDS; ++i)
        SIPROUND;

    v0 ^= b;

    if (OUTLEN == 16)
        v2 ^= 0xee;
    else
        v2 ^= 0xff;

    TRACE;
    for (i = 0; i < dROUNDS; ++i)
        SIPROUND;

    b = v0 ^ v1 ^ v2 ^ v3;
    U64TO8_LE(out, b);
}
