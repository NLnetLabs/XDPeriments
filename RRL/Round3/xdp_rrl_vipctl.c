#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <bpf.h>
#include <libbpf.h>

static const uint8_t zeros[16] = { 0 };

struct key_type {
	uint32_t prefixlen;
	uint8_t  ip_addr[16];
	int      map_fd;
};

int print_usage(int ret_code, const char *progname)
{
	FILE *out = ret_code == EXIT_SUCCESS ? stdout : stderr;
	fprintf(out, "usage:\n"
	             "\t%s export > \"prefixes.txt\"\n"
	             "\t%s import < \"prefixes.txt\"\n"
	             "\t%s add <prefix>\n"
	             "\t%s del <prefix>\n"
	           , progname, progname, progname, progname);
	return ret_code;
}

int export_prefixes(int argc, char **argv, int map4_fd, int map6_fd)
{
	struct key_type key = { 0 };
	void *keyp = &key, *prev_keyp = NULL;
	char ipv4_str[16];
	char ipv6_str[40];

	if (argc != 2)
		return print_usage(EXIT_FAILURE, argv[0]);

	while (!bpf_map_get_next_key(map4_fd, prev_keyp, keyp)) {
		printf( "%s/%"PRIu32"\n"
		      , inet_ntop( AF_INET ,  &key.ip_addr
				 , ipv4_str, sizeof(ipv4_str))
		      , key.prefixlen);
		prev_keyp = keyp;
	}
	if (errno != ENOENT) {
		fprintf(stderr, "Error get next map key: %s\n"
			      , strerror(errno));
		return EXIT_FAILURE;
	}
	keyp = &key;
	prev_keyp = NULL;
	while (!bpf_map_get_next_key(map6_fd, prev_keyp, keyp)) {
		printf( "%s/%"PRIu32"\n"
		      , inet_ntop( AF_INET6,  &key.ip_addr
				 , ipv6_str, sizeof(ipv6_str))
		      , key.prefixlen);
		prev_keyp = keyp;
	}
	if (errno != ENOENT) {
		fprintf(stderr, "Error get next map key: %s\n"
			      , strerror(errno));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int prefix2key_(const char *ip_addr, long len, int map4_fd, int map6_fd,
		struct key_type *key)
{
	if (inet_pton(AF_INET, ip_addr, &key->ip_addr)) {
		key->map_fd = map4_fd;
		key->prefixlen = len < 0 ? 32 : len;
		if (len == 0 || len > 32)
			fprintf(stderr, "Prefix length must be <= 32: %s/%li\n"
			              , ip_addr, len);
		else
			return EXIT_SUCCESS;

	} else if (inet_pton(AF_INET6, ip_addr, &key->ip_addr)) {
		key->map_fd = map6_fd;
		key->prefixlen = len < 0 ? 64 : len;
		if (len == 0 || len > 64)
			fprintf(stderr, "Prefix length must be <= 64: %s/%li\n"
			              , ip_addr, len);
		else
			return EXIT_SUCCESS;

	} else if (len >= 0)
		fprintf(stderr, "Syntax error in prefix: %s/%li\n"
		              , ip_addr, len);
	else
		fprintf(stderr, "Syntax error in prefix: %s\n", ip_addr);

	return EXIT_FAILURE;
}

int prefix2key(const char *prefix, int map4_fd, int map6_fd,
		struct key_type *key)
{
	const char *slashp = strchr(prefix, '/');
	char ip_addr[40];
	char *endptr;
	long len;

	if (slashp && slashp - prefix > 39)
		fprintf(stderr, "Syntax error in prefix: %s\n", prefix);

	else if (!slashp) {
		if (prefix2key_(prefix, -1, map4_fd, map6_fd, key))
			; /* pass */
		else
			return EXIT_SUCCESS;

	} else if (!(len = strtoul(slashp + 1, &endptr, 10)))
		fprintf(stderr, "Prefix length must be > 0: %s\n", prefix);
 
	else if (!slashp[1] || !endptr || *endptr)
		fprintf(stderr, "Syntax error in prefix length: %s\n", prefix);
	else {
		memcpy(ip_addr, prefix, slashp - prefix);
		ip_addr[slashp - prefix] = 0;
		if (prefix2key_(ip_addr, len, map4_fd, map6_fd, key))
			; /* pass */
		else
			return EXIT_SUCCESS;
	}
	return EXIT_FAILURE;
}

int add_prefix_(const char *prefix, int map4_fd, int map6_fd)
{
	struct key_type key = { 0 };

	if (prefix2key(prefix, map4_fd, map6_fd, &key))
		; /* pass */

	else if (bpf_map_update_elem(key.map_fd, &key, zeros, 0) < 0)
		fprintf(stderr, "Could not add prefix %s: %s\n"
		              , prefix, strerror(errno));
	else
		return EXIT_SUCCESS;

	return EXIT_FAILURE;
}

int add_prefix(int argc, char **argv, int map4_fd, int map6_fd)
{
	if (argc != 3)
		return print_usage(EXIT_FAILURE, argv[0]);

	return add_prefix_(argv[2], map4_fd, map6_fd);
}

int del_prefix_(const char *prefix, int map4_fd, int map6_fd)
{
	struct key_type key = { 0 };

	if (prefix2key(prefix, map4_fd, map6_fd, &key))
		; /* pass */

	else if (bpf_map_delete_elem(key.map_fd, &key) < 0)
		fprintf(stderr, "Could not del prefix %s: %s\n"
		              , prefix, strerror(errno));
	else
		return EXIT_SUCCESS;

	return EXIT_FAILURE;
}

int del_prefix(int argc, char **argv, int map4_fd, int map6_fd)
{
	if (argc != 3)
		return print_usage(EXIT_FAILURE, argv[0]);

	return del_prefix_(argv[2], map4_fd, map6_fd);
}

int main(int argc, char **argv)
{
	char *fn4 = "/sys/fs/bpf/rrl_exclude_v4_prefixes";
	char *fn6 = "/sys/fs/bpf/rrl_exclude_v6_prefixes";
	int map4_fd, map6_fd;
	struct bpf_map_info info4, info6;
	uint32_t info4_len = sizeof(info4), info6_len = sizeof(info6);
	if ((map4_fd = bpf_obj_get(fn4)) < 0)
		fprintf(stderr, "Error opening \"%s\": %s\n"
		              , fn4, strerror(errno));

	else if (bpf_obj_get_info_by_fd(map4_fd, &info4, &info4_len))
		fprintf(stderr, "Cannot get info from \"%s\": %s\n"
		              , fn4, strerror(errno));

	else if (info4.type != BPF_MAP_TYPE_LPM_TRIE || info4.key_size != 8)
		fprintf(stderr, "Map \"%s\" had wrong type\n", fn4);

	else if ((map6_fd = bpf_obj_get(fn6)) < 0)
		fprintf(stderr, "Error opening \"%s\": %s\n"
		              , fn6, strerror(errno));

	else if (bpf_obj_get_info_by_fd(map6_fd, &info6, &info6_len))
		fprintf(stderr, "Cannot get info from \"%s\": %s\n"
		              , fn6, strerror(errno));

	else if (info6.type != BPF_MAP_TYPE_LPM_TRIE || info6.key_size != 12)
		fprintf(stderr, "Map \"%s\" had wrong type\n", fn6);

	else if (argc < 2)
		return print_usage(EXIT_SUCCESS, argv[0]);

	else if (!strcmp(argv[1], "export"))
		return export_prefixes(argc, argv, map4_fd, map6_fd);

	else if (!strcmp(argv[1], "add"))
		return add_prefix(argc, argv, map4_fd, map6_fd);

	else if (!strcmp(argv[1], "del"))
		return del_prefix(argc, argv, map4_fd, map6_fd);
	else
		print_usage(EXIT_FAILURE, argv[0]);

	return EXIT_FAILURE;
}
