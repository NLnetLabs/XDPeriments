#include <stdio.h>
#include <inttypes.h>
#include <bpf.h>
#include <libbpf.h>
#include <errno.h>
#include "stats_key.h"

int print_stats(int map_fd)
{
	struct stats_key sk = { 0 };
	void *keyp = &sk, *prev_keyp = NULL;

    // Specify the prometheus metric types
    printf("# TYPE queries_total counter\n");

    uint64_t cnt = 0;
	while (!bpf_map_get_next_key(map_fd, prev_keyp, keyp)) {

		bpf_map_lookup_elem(map_fd, &sk, &cnt);
    char* edns_bin = "undefined";
    if (sk.no_edns == 1)
        edns_bin = "no_edns";
    else if (sk.edns_size_leq1231 == 1) 
        edns_bin = "leq1231";
    else if (sk.edns_size_1232 == 1) 
        edns_bin = "1232";
    else if (sk.edns_size_leq1399 == 1) 
        edns_bin = "leq1399";
    else if (sk.edns_size_1400 == 1) 
        edns_bin = "1400";
    else if (sk.edns_size_leq1499 == 1) 
        edns_bin = "leq1499";
    else if (sk.edns_size_1500 == 1) 
        edns_bin = "1500";
    else if (sk.edns_size_gt1500 == 1) 
        edns_bin = "gt1500";

    printf("queries_total{af=%i, qtype=%i, qr_bit=%i, do_bit=%i, ad_bit=%i, edns_bin=%s, tld=%s} %ld\n",
            sk.af,
            sk.qtype,
            sk.qr_bit,
            sk.do_bit,
            sk.ad_bit,
            edns_bin,
            sk.tld,
            cnt);

		prev_keyp = keyp;
	}

    return 0;
}

int main(int argc, char **argv)
{
	char *fn = "/sys/fs/bpf/stats";
	int map_fd;
	struct bpf_map_info info = {}; // https://stackoverflow.com/questions/60654466/bpf-bpf-obj-get-info-by-fd-fails-with-invalid-argument
	uint32_t info_len = sizeof(info);

    if ((map_fd = bpf_obj_get(fn)) < 0)
        fprintf(stderr, "Error opening \"%s\": %s\n"
                , fn, strerror(errno));
    else if (bpf_obj_get_info_by_fd(map_fd, &info, &info_len))
        fprintf(stderr, "Cannot get info from \"%s\": %s\n"
                , fn, strerror(errno));
    else 
        print_stats(map_fd);
}
