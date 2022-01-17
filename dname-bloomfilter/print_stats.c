#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <bpf.h>
#include <libbpf.h>

#include "diagnostics.h"

#define DNAMES_PINPATH "/sys/fs/bpf/tc/globals/dnames"
#define DIAG_PINPATH "/sys/fs/bpf/tc/globals/diagnostics"

#ifndef NUM_CPUS
#define NUM_CPUS 8
#endif

__always_inline
void pretty_dname(char* dname)
{

    char len;
    int i = 0;
	while (i < 255) {
        len = dname[i];
        if (len == 0) break;

        // do not print a . for the first length byte
        if (i > 0)
            printf(".");

        for (int j = 0; j < len; j++) {
            i++;
            if (isprint((int)dname[i]))
                printf("%c", dname[i]);
            else {
                printf("\\%03u", (uint8_t) dname[i]);
            }
        }
        i++;
    }
}
__always_inline
int print_dnames(int dnames_fd)
{
	char key[255] = { 0 };
	void *keyp = &key, *prev_keyp = NULL;
    if (NUM_CPUS <= 0) return EXIT_FAILURE;

	uint64_t counts[NUM_CPUS];
    while (!bpf_map_get_next_key(dnames_fd, prev_keyp, keyp)) {
        bpf_map_lookup_elem(dnames_fd, &key, counts);

        uint64_t count = 0;
        for (int i = 0; i < NUM_CPUS; i++) {
            count += counts[i];
        }
        if (count > 0) {
            printf("dname{dname=\"");
            pretty_dname(key);
            printf("\"} %lu\n", count);
        }

        prev_keyp = keyp;
    }

	return 0;

}

__always_inline
int print_diagnostics(int diagnostics_fd)
{
	int diag_index;
	uint64_t value = 0; 	

    diag_index = DIAG_BLOOMCOUNT;
	bpf_map_lookup_elem(diagnostics_fd, &diag_index, &value);
    printf("diag_bloomfilter_elements %ld\n", value);

    diag_index = DIAG_HIT;
	bpf_map_lookup_elem(diagnostics_fd, &diag_index, &value);
    printf("diag_bloomfilter_hits %ld\n", value);

    diag_index = DIAG_OVERFLOW;
	bpf_map_lookup_elem(diagnostics_fd, &diag_index, &value);
    printf("diag_bloomfilter_overflows %ld\n", value);

	return 0;
}


int main(int argc, char **argv)
{

	struct bpf_map_info dnames;
	struct bpf_map_info diagnostics;

	uint32_t dnames_info = sizeof(dnames), dnames_len = sizeof(dnames);
	int dnames_fd;

	uint32_t diagnostics_info = sizeof(diagnostics), diagnostics_len = sizeof(diagnostics);
	int diagnostics_fd;


	if ((dnames_fd = bpf_obj_get(DNAMES_PINPATH)) < 0)
        fprintf(stderr, "Error opening %s: %s", DNAMES_PINPATH, strerror(errno));
	else if (bpf_obj_get_info_by_fd(dnames_fd, &dnames_info, &dnames_len))
        fprintf(stderr, "Cannot get info from \"%s\": %s\n" , DNAMES_PINPATH, strerror(errno));
	else if ((diagnostics_fd = bpf_obj_get(DIAG_PINPATH)) < 0)
        fprintf(stderr, "Error opening %s: %s", DIAG_PINPATH, strerror(errno));
	else if (bpf_obj_get_info_by_fd(diagnostics_fd, &diagnostics_info, &diagnostics_len))
        fprintf(stderr, "Cannot get info from \"%s\": %s\n" , DIAG_PINPATH, strerror(errno));
	else {
		print_dnames(dnames_fd);
		print_diagnostics(diagnostics_fd);
	}

    return EXIT_SUCCESS;
}
