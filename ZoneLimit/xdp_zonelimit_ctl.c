#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <bpf.h>
#include <libbpf.h>

int print_usage(int ret_code, const char *progname)
{
	FILE *out = ret_code == EXIT_SUCCESS ? stdout : stderr;
	fprintf(out, "usage:\n"
	             "\t%s list \n"
	             "\t%s add <dname>\n"
	             "\t%s del <dname>\n"
	           ,progname, progname, progname);
	return ret_code;
}

#ifndef DEFAULT_IFACE
#define DEFAULT_IFACE "eth0"
#endif

#define JMP_TBL "jmp_table"
#define ZONELIMIT_DNAMES "zonelimit_dnames"

#define NAMELEN 64+64+4 +4 // 4 for padding?

struct key_type {
    uint32_t prefixlen;
    char dname[NAMELEN];
};


int str_to_key(char *str, struct key_type *key)
{
    char *kp = key->dname;

    char c;
    int32_t i, j = 1;
    uint32_t lbllen = 0;
    uint32_t lblstart = 0;
    uint8_t lblcnt = 0;

    // we process the input string backwards
    for (i = strlen(str) - 1; i >= 0; i--) {
        c = str[i];
        if (c == '.') {
            // label boundary: write the length to the 'lblstart' index
            kp[lblstart] = (char)lbllen;
            lblcnt++;
            // copy the actual label from the input string into kp
            memcpy(kp + lblstart + 1, str + strlen(str) - j + 1, lbllen);
            // reset the label len counter 
            lbllen = 0;
            // and record the index of where the next label length byte will go:
            lblstart = j;
        } else {
            lbllen += 1;
            if (lbllen > 63) {
                fprintf(stderr, "ERROR: illegal label length, max is 63\n");
                return -1;
            }
        }
        j++;
        if (i == 0) {
            // last char of input, create a label of it and be done
            kp[lblstart] = (char)lbllen;
            lblcnt++;
            memcpy(kp + lblstart + 1, str + strlen(str) - j + 1, lbllen);
        }
    }

    return lblcnt;
}

int add_dname(int argc, char **argv, int map_fd)
{
    if (argc != 3)
        return print_usage(EXIT_FAILURE, argv[0]);

    struct key_type k = { .prefixlen = 0 };
    int lblcnt = str_to_key(argv[2], &k);

    if (lblcnt < 0) {
        return EXIT_FAILURE;
    }
    if (lblcnt > 3) {
        fprintf(stderr, "ERROR: Can only add dnames with up to three labels"); 
        return EXIT_FAILURE;
    }
    if (k.prefixlen > 64+64+4) {
        fprintf(stderr, "ERROR: Can only add dnames of length 64+64+4 (three labels) total"); 
        return EXIT_FAILURE;
    }

    printf("adding key %s\n", k.dname);

    k.prefixlen = strlen(k.dname) * 8;
    uint64_t zero = 0;
    if (bpf_map_update_elem(map_fd, &k, &zero, 0) < 0) {
        fprintf(stderr, "ERROR: failed to add dname: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int del_dname(int argc, char **argv, int map_fd)
{
    if (argc != 3)
        return print_usage(EXIT_FAILURE, argv[0]);

    struct key_type k = { .prefixlen = 0 };
    str_to_key(argv[2], &k);

    printf("deleting key %s\n", k.dname);

    k.prefixlen = strlen(k.dname)*8;
    if (bpf_map_delete_elem(map_fd, &k) < 0) {
        fprintf(stderr, "failed to remove dname: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int list_dnames(int argc, char **argv, int map_fd)
{

    if (argc != 2)
        return print_usage(EXIT_FAILURE, argv[0]);

    struct key_type key = { 0 };
    void *keyp = &key, *prev_keyp = NULL;
    keyp = &key;
    prev_keyp = NULL;
    uint8_t i, lblcnt = 0;
    uint8_t lbls[10];
    uint64_t hitcount = 0;
	while (!bpf_map_get_next_key(map_fd, prev_keyp, keyp)) {
        bpf_map_lookup_elem(map_fd, &key, &hitcount);
        for(i = 0; i < strlen(key.dname);  i++) {
            lbls[++lblcnt] = i;
            i += key.dname[i];
        }

        for(i = lblcnt; i > 0; i--){
            printf("%.*s.", (uint8_t)key.dname[lbls[i]], &key.dname[lbls[i]+1]);
        }
        int padding = 25 - strlen(key.dname);
        printf("%*lu\n", padding, hitcount);

		prev_keyp = keyp;
        lblcnt = hitcount = 0;
    }
    printf("--------\n");

    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	struct bpf_map *dname_map = NULL;
    const char *dname_map_fn = "/sys/fs/bpf/zonelimit_dnames";

    int map_fd;
    struct bpf_map_info info;
    uint32_t info_len = sizeof(info);

	const char *ifname = DEFAULT_IFACE;
	unsigned int ifindex = 0;

	struct bpf_program *prog = NULL;
	const char *xdp_program_name = NULL;
	struct bpf_object  *obj  = NULL;
	int fd = -1, jmp_tbl_fd = -1;
	uint32_t key = 0;

    if (argc < 2)
        return print_usage(EXIT_SUCCESS, argv[0]);
    else if ((map_fd = bpf_obj_get(dname_map_fn)) < 0)
        fprintf(stderr, "Failed to open %s: %s\n", dname_map_fn, strerror(errno));
    else if(bpf_obj_get_info_by_fd(map_fd, &info, &info_len))
        fprintf(stderr, "get_info fail for %s: %s\n", dname_map_fn, strerror(errno));
    else if(!strcmp(argv[1], "load")) {

		if (!(ifindex = if_nametoindex(ifname)))
			fprintf(stderr, "ERROR: error finding device %s: %s\n"
					, ifname, strerror(errno));

		else if (!(obj = bpf_object__open_file("xdp_zonelimit.o", NULL))
				|| libbpf_get_error(obj))
			fprintf(stderr, "ERROR: opening BPF object file failed\n");

		else if (!(dname_map = bpf_object__find_map_by_name(obj, ZONELIMIT_DNAMES)))
			fprintf(stderr, "ERROR: table " ZONELIMIT_DNAMES " not found\n");
		else if (bpf_map__set_pin_path(dname_map, dname_map_fn))
			fprintf(stderr, "ERROR: pinning " ZONELIMIT_DNAMES " to \"%s\"\n"
					, dname_map_fn);

		fprintf(stderr, "here 0\n");
		if (bpf_object__load(obj))
			fprintf(stderr, "ERROR: loading BPF object file failed\n");

		fprintf(stderr, "here 1\n");
		if ((jmp_tbl_fd = bpf_object__find_map_fd_by_name(obj, JMP_TBL)) < 0){
			fprintf(stderr, "ERROR: table " JMP_TBL " not found\n");
		} else {
			fprintf(stderr,"2");
			bpf_object__for_each_program(prog, obj) {
				xdp_program_name = bpf_program__section_name(prog);

				fd = bpf_program__fd(prog);
				printf(JMP_TBL " entry: %d -> %s\n", key, xdp_program_name);
				if (bpf_map_update_elem(jmp_tbl_fd, &key, &fd, BPF_ANY) < 0){
					fprintf( stderr
							, "ERROR: making " JMP_TBL " entry for %s\n"
							, xdp_program_name);
					fd = -1;
					break;
				}
				key++;
			}
		}
		if (fd < 0)
			; /* earlier error */

		else if (bpf_set_link_xdp_fd(ifindex, fd, 0))
			fprintf(stderr, "ERROR: attaching xdp program to device\n");
		else {
			printf("%s successfully loaded and running on interface %s.\n"
					, xdp_program_name, ifname);
			printf("Press Ctrl-C to stop and unload.\n");
			while (true)
				sleep(60);
		}
	}
    else if(!strcmp(argv[1], "add"))
        return add_dname(argc, argv, map_fd);
    else if(!strcmp(argv[1], "del"))
        return del_dname(argc, argv, map_fd);
    else if(!strcmp(argv[1], "list"))
        return list_dnames(argc, argv, map_fd);
    else
        print_usage(EXIT_FAILURE, argv[0]);

    return EXIT_FAILURE;

}
