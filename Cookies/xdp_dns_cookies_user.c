#include <net/if.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <bpf.h>
#include <libbpf.h>

#ifndef DEFAULT_IFACE
#define DEFAULT_IFACE "eth0"
#endif
#define DEFAULT_IPv4_VIP_PINPATH "/sys/fs/bpf/rrl_exclude_v4_prefixes"
#define DEFAULT_IPv6_VIP_PINPATH "/sys/fs/bpf/rrl_exclude_v6_prefixes"

#define JMP_TBL "jmp_table"
#define EXCLv4_TBL "exclude_v4_prefixes"
#define EXCLv6_TBL "exclude_v6_prefixes"

void print_usage(FILE *out, const char *program_name)
{
	fprintf( out
	       , "Usage: %s [-i interface] [-4 IPv4 V.I.P. pinpath]"
	                                 " [-6 IPv6 V.I.P. pinpath]\n"
	         "Default values:\n"
	         "  - interface: " DEFAULT_IFACE "\n"
	         "  - IPv4 V.I.P. pinpath: \"" DEFAULT_IPv4_VIP_PINPATH "\"\n"
	         "  - IPv6 V.I.P. pinpath: \"" DEFAULT_IPv6_VIP_PINPATH "\"\n"
	       , program_name);
}

int main(int argc, char *argv[])
{
	const char *ifname = DEFAULT_IFACE;
	const char *exclude_v4_pinpath = DEFAULT_IPv4_VIP_PINPATH;
	const char *exclude_v6_pinpath = DEFAULT_IPv6_VIP_PINPATH;
	int opt = -1;

	unsigned int ifindex = 0;
	struct bpf_program *prog = NULL;
	struct bpf_object  *obj  = NULL;
	struct bpf_map *exclude_v4 = NULL;
	struct bpf_map *exclude_v6 = NULL;
	const char *xdp_program_name = NULL;
	int fd = -1, jmp_tbl_fd = -1;
	uint32_t key = 0;

	while ((opt = getopt(argc, argv, "hi:4:6:")) != -1) {
		switch(opt) {
		case 'i':
			ifname = optarg;
			break;
		case '4':
			exclude_v4_pinpath = optarg;
			break;
		case '6':
			exclude_v4_pinpath = optarg;
			break;
		case 'h':
			print_usage(stdout, argv[0]);
			exit(EXIT_SUCCESS);
		default:
			fprintf(stderr, "OPT: %d ('%c')\n", opt, (char)opt);
			print_usage(stderr, argv[0]);
			exit(EXIT_FAILURE);
		}
	}
	if (!(ifindex = if_nametoindex(ifname)))
		fprintf(stderr, "ERROR: error finding device %s: %s\n"
		              , ifname, strerror(errno));

	else if (!(obj = bpf_object__open_file("xdp_dns_cookies_kern.o", NULL))
	|| libbpf_get_error(obj))
		fprintf(stderr, "ERROR: opening BPF object file failed\n");

	else if (!(exclude_v4 = bpf_object__find_map_by_name(obj, EXCLv4_TBL)))
		fprintf(stderr, "ERROR: table " EXCLv4_TBL " not found\n");

	else if (bpf_map__set_pin_path(exclude_v4, exclude_v4_pinpath))
		fprintf(stderr, "ERROR: pinning " EXCLv4_TBL " to \"%s\"\n"
		              , exclude_v4_pinpath);

	else if (!(exclude_v6 = bpf_object__find_map_by_name(obj, EXCLv6_TBL)))
		fprintf(stderr, "ERROR: table " EXCLv6_TBL " not found\n");

	else if (bpf_map__set_pin_path(exclude_v6, exclude_v6_pinpath))
		fprintf(stderr, "ERROR: pinning " EXCLv6_TBL " to \"%s\"\n"
		              , exclude_v6_pinpath);

	else if (bpf_object__load(obj))
		fprintf(stderr, "ERROR: loading BPF object file failed\n");

	else if ((jmp_tbl_fd = bpf_object__find_map_fd_by_name(obj, JMP_TBL)) < 0)
		fprintf(stderr, "ERROR: table " JMP_TBL " not found\n");

	else bpf_object__for_each_program(prog, obj) {
		xdp_program_name = bpf_program__title(prog, false);
		
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
	return EXIT_FAILURE;
}
