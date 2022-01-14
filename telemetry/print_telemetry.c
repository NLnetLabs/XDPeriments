#include <stdio.h>
#include <inttypes.h>
#include <bpf.h>
#include <libbpf.h>
#include <errno.h>

struct stats_key {
    uint8_t af;
    uint8_t opcode;
    uint8_t rcode;
    uint8_t qtype;
    uint16_t msgsize;
    char tld[10];
};

int print_stats(int map_fd)
{
	struct stats_key sk = { 0 };
	void *keyp = &sk, *prev_keyp = NULL;

    // Specify the prometheus metric types
    printf("# TYPE queries_total counter\n");

    uint64_t cnt = 0;
	while (!bpf_map_get_next_key(map_fd, prev_keyp, keyp)) {

		bpf_map_lookup_elem(map_fd, &sk, &cnt);
        printf("queries_total{af=%i, opcode=%i, rcode=%i, qtype=%i, msgsize=%i, tld=%s} %ld\n",
                sk.af,
                sk.opcode,
                sk.rcode,
                sk.qtype,
                sk.msgsize,
                sk.tld,
                cnt);

        //PRINT_STAT6("query_count", key6, qtype, A, value);
		prev_keyp = keyp;
	}

    return 0;
}

int main(int argc, char **argv)
{
	char *fn = "/sys/fs/bpf/tc/globals/stats";
	int map_fd;
	struct bpf_map_info info;
	uint32_t info_len = sizeof(info);

    if ((map_fd = bpf_obj_get(fn)) < 0)
        fprintf(stderr, "Error opening \"%s\": %s\n"
                , fn, strerror(errno));

    else if (bpf_obj_get_info_by_fd(map_fd, &info, &info_len))
        fprintf(stderr, "Cannot get info from \"%s\": %s\n"
                , fn, strerror(errno));
    else {
        print_stats(map_fd);
    }
}
