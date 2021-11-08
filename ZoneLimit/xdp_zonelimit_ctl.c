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

#define NAMELEN 200

struct key_type {
    uint32_t prefixlen;
    char dname[NAMELEN];
};
int add_dname(int argc, char **argv, int map_fd)
{
    if (argc != 3)
        return print_usage(EXIT_FAILURE, argv[0]);

    // adding foo.test.com
    // should result in an entry
    // \03com\04test\03foo

    struct key_type k = { .prefixlen = 0 };
    char *key = k.dname;

    char c;
    int8_t i, j = 1;
    uint8_t lbllen = 0;
    uint8_t lblstart = 0;

    for (i = strlen(argv[2]) - 1; i >= 0; i--) {
        c = argv[2][i];
        if (c == '.') {
            // label boundary: write the length to the 'lblstart' index
            key[lblstart] = (char)lbllen;
            // copy the actual label from the input string into key
            memcpy(key + lblstart + 1, argv[2] + strlen(argv[2]) - j + 1, lbllen);
            // reset the label len counter 
            lbllen = 0;
            // and record the index of where the next label length byte will go:
            lblstart = j;
        } else {
            lbllen += 1;
        }
        j++;
        if (i == 0) {
            // last char of input, create a label of it and be done
            key[lblstart] = (char)lbllen;
            memcpy(key + lblstart + 1, argv[2] + strlen(argv[2]) - j + 1, lbllen);
        }
    }
    printf("adding key %s\n", key);

    k.prefixlen = strlen(argv[2])*8;
    uint64_t zero = 0;
    if (bpf_map_update_elem(map_fd, &k, &zero, 0) < 0) {
        fprintf(stderr, "failed to add dname: %s\n", strerror(errno));
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
	while (!bpf_map_get_next_key(map_fd, prev_keyp, keyp)) {
        printf("%s\n", key.dname);

        for(i = 0; i < strlen(key.dname);  i++) {
            lbls[lblcnt++] = i;
            i += key.dname[i];
        }
        printf("lblcnt: %i\n", lblcnt);
        for(i = lblcnt; i > 0; i--){
            printf("lbl %s\n", &key.dname[lbls[i]]);
        }

		prev_keyp = keyp;
        lblcnt = 0;
    }
    printf("--------\n");

    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    char *fn = "/sys/fs/bpf/zonelimit_dnames";
    int map_fd;
    struct bpf_map_info info;
    uint32_t info_len = sizeof(info);

    if (argc < 2)
        return print_usage(EXIT_SUCCESS, argv[0]);
    else if ((map_fd = bpf_obj_get(fn)) < 0)
        fprintf(stderr, "Failed to open %s: %s\n", fn, strerror(errno));
    else if(bpf_obj_get_info_by_fd(map_fd, &info, &info_len))
        fprintf(stderr, "get_info fail for %s: %s\n", fn, strerror(errno));
    else if(!strcmp(argv[1], "add"))
        return add_dname(argc, argv, map_fd);
    else if(!strcmp(argv[1], "list"))
        return list_dnames(argc, argv, map_fd);
    else
        print_usage(EXIT_FAILURE, argv[0]);

    return EXIT_FAILURE;

}
