#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <bpf.h>
#include <libbpf.h>

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

struct key6_type {
	uint32_t prefixlen;
	uint8_t  ip_addr[40];
};
struct key4_type {
	uint32_t prefixlen;
	uint8_t  ip_addr[16];
};

#define PRINT_STAT6(metric, key, lname, lval, val) {\
    printf( "%s{subnet=\"%s/%i\", %s=\"%s\"} %i\n",\
            metric,\
            inet_ntop( AF_INET6,  &key.ip_addr, ipv6_str, sizeof(ipv6_str)),\
            key.prefixlen,\
            #lname,\
            #lval,\
            val.lname.lval\
          );\
    }
#define PRINT_STAT4(metric, key, lname, lval, val) {\
    printf( "%s{subnet=\"%s/%i\", %s=\"%s\"} %i\n",\
            metric,\
            inet_ntop( AF_INET,  &key.ip_addr, ipv4_str, sizeof(ipv4_str)),\
            key.prefixlen,\
            #lname,\
            #lval,\
            val.lname.lval\
          );\
    }

int print_stats(int map6_fd, int map4_fd) 
{
	struct key6_type key6 = { 0 };
	struct key4_type key4 = { 0 };
	void *keyp = &key6, *prev_keyp = NULL;
	char ipv6_str[40];
	char ipv4_str[16];

    // Specify the metric types
    printf("# TYPE query_count counter\n");

    // print IPv6 stats
	while (!bpf_map_get_next_key(map6_fd, prev_keyp, keyp)) {
        struct stats value = {0};

		bpf_map_lookup_elem(map6_fd, &key6, &value);
        PRINT_STAT6("query_count", key6, qtype, A, value);
        PRINT_STAT6("query_count", key6, qtype, AAAA, value);
        PRINT_STAT6("query_count", key6, qtype, other, value);

        PRINT_STAT6("query_count", key6, qsize, lt50, value);
        PRINT_STAT6("query_count", key6, qsize, lt75, value);
        PRINT_STAT6("query_count", key6, qsize, lt100, value);
        PRINT_STAT6("query_count", key6, qsize, lt200, value);
        PRINT_STAT6("query_count", key6, qsize, lt500, value);
        PRINT_STAT6("query_count", key6, qsize, lt1000, value);
        PRINT_STAT6("query_count", key6, qsize, gt1000, value);

		prev_keyp = keyp;
	}

    // reset the key for iteration over the v4 stats
    keyp = &key4;
    prev_keyp = NULL;

    // print IPv4 stats
	while (!bpf_map_get_next_key(map4_fd, prev_keyp, keyp)) {
        struct stats value = {0};

		bpf_map_lookup_elem(map4_fd, &key4, &value);
        PRINT_STAT4("query_count", key4, qtype, A, value);
        PRINT_STAT4("query_count", key4, qtype, AAAA, value);
        PRINT_STAT4("query_count", key4, qtype, other, value);

        PRINT_STAT4("query_count", key4, qsize, lt50, value);
        PRINT_STAT4("query_count", key4, qsize, lt75, value);
        PRINT_STAT4("query_count", key4, qsize, lt100, value);
        PRINT_STAT4("query_count", key4, qsize, lt200, value);
        PRINT_STAT4("query_count", key4, qsize, lt500, value);
        PRINT_STAT4("query_count", key4, qsize, lt1000, value);
        PRINT_STAT4("query_count", key4, qsize, gt1000, value);

		prev_keyp = keyp;
	}
    return 0;
}

int main(int argc, char **argv)
{
	char *fn6 = "/sys/fs/bpf/stats_v6";
	char *fn4 = "/sys/fs/bpf/stats_v4";
	int map6_fd, map4_fd;
	struct bpf_map_info info6, info4;
	uint32_t info6_len = sizeof(info6), info4_len = sizeof(info4);

    if ((map6_fd = bpf_obj_get(fn6)) < 0)
        fprintf(stderr, "Error opening \"%s\": %s\n"
                , fn6, strerror(errno));

    else if (bpf_obj_get_info_by_fd(map6_fd, &info6, &info6_len))
        fprintf(stderr, "Cannot get info from \"%s\": %s\n"
                , fn6, strerror(errno));

    else if (info6.type != BPF_MAP_TYPE_LPM_TRIE || info6.key_size != 12)
        fprintf(stderr, "Map \"%s\" had wrong type\n", fn6);

    else if ((map4_fd = bpf_obj_get(fn4)) < 0)
        fprintf(stderr, "Error opening \"%s\": %s\n"
                , fn4, strerror(errno));

    else if (bpf_obj_get_info_by_fd(map4_fd, &info4, &info4_len))
        fprintf(stderr, "Cannot get info from \"%s\": %s\n"
                , fn4, strerror(errno));

    else if (info4.type != BPF_MAP_TYPE_LPM_TRIE || info4.key_size != 8)
        fprintf(stderr, "Map \"%s\" had wrong type\n", fn4);
    else
        print_stats(map6_fd, map4_fd);

    return EXIT_SUCCESS;
}

