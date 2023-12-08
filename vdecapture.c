/*
 * vdecapture: capture vde traffic in pcap format
 * Copyright (C) 2023  Renzo Davoli, Virtualsquare
 *
 * randmac is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <libvdeplug.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <sys/time.h>
#include <pcap/pcap.h>

#define PCAP_MAGIC 0xa1b2c3d4
#define SNAPLEN 65535
#define VERSION_MAJOR 2
#define VERSION_MINOR 4
#define UNUSED 0

struct pcap_pkthdr_filefmt {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
  uint32_t caplen; /* length of portion present */
  uint32_t len;  /* length of this packet (off wire) */
};

#define VDECAPTURE_FLAG_QUIET   0x1
#define VDECAPTURE_FLAG_APPEND  0x2

struct options {
	int maxcount;
	size_t maxlen;
	time_t maxtime;
	int flags;
};

int terminate = 0;
int reload = 0;

void sighandler(int signo) {
	if (signo == SIGHUP)
		reload = 1;
	else
		terminate = 1;
}

static FILE *open_outfile(char *path, int append) {
	FILE *f;
	struct pcap_file_header hdr = {
		PCAP_MAGIC,
		VERSION_MAJOR, VERSION_MINOR,
		UNUSED, UNUSED,
		SNAPLEN,
		1};
	if (strcmp(path, "-") == 0) {
    f = stdout;
		fwrite(&hdr, sizeof(hdr), 1, f);
	} else if (append) {
		f = fopen(path, "a+");
		if (f) {
			struct pcap_file_header filehdr;
			size_t hdrlen = fread(&filehdr, 1, sizeof(filehdr), f);
			if (hdrlen == 0)
				fwrite(&hdr, sizeof(hdr), 1, f);
			else if (hdrlen != sizeof(filehdr) ||
					memcmp(&hdr, &filehdr, sizeof(hdr)) != 0) {
				fclose(f);
				return errno = EBADF, NULL;
			}
		}
	} else {
		f = fopen(path, "w+");
		if (f)
			fwrite(&hdr, sizeof(hdr), 1, f);
	}
	return f;
}

static int mainloop(char *vnl, char *outpath, struct options *options) {
	int count = 0;
	size_t outlen = 0;
	char buf[SNAPLEN];
	FILE *f;
	VDECONN *conn = vde_open(vnl, "vdecapture", NULL);
	if (conn == NULL) {
		fprintf(stderr, "vde_open error\n");
		goto err_vde;
	}
	f = open_outfile(outpath, !!(options->flags & VDECAPTURE_FLAG_APPEND));
	if (f == NULL) {
		perror(outpath);
		goto err_file;
	}

	if (options->maxtime > 0)
		alarm(options->maxtime);
	struct pollfd fds[] = {{vde_datafd(conn), POLLIN, 0}, {fileno(f), POLLERR, 0}};

	while(terminate == 0) {
		poll(fds, 2, 1000);
		if (fds[0].revents & POLLIN) {
			ssize_t n = vde_recv(conn, buf, SNAPLEN, 0);
			if (n <= 0) break;
			struct timeval tv;
			gettimeofday(&tv, NULL);
			struct pcap_pkthdr_filefmt phdr = {tv.tv_sec, tv.tv_usec, n, n};
			outlen += n + sizeof(phdr);
			if (options->maxlen > 0 && outlen > options->maxlen)
				break;
			if (fwrite(&phdr, sizeof(phdr), 1, f) == 0)
				break;
			if (fwrite(buf, n, 1, f) == 0)
				break;
			count++;
			if (isatty(STDERR_FILENO) && !(options->flags & VDECAPTURE_FLAG_QUIET))
				fprintf(stderr, "\r%d", count);
			if (options->maxcount > 0 && count >= options->maxcount)
				break;
		} else if (fds[1].revents & POLLERR) 
			break;
		else
			fflush(f);
		if (reload) {
			reload = 0;
			if (strcmp(outpath, "-") != 0) {
				fclose(f);
				f = open_outfile(outpath, !!(options->flags & VDECAPTURE_FLAG_APPEND));
				if (f == NULL) {
					perror(outpath);
					goto err_file;
				}
			}
		}
	}
	if (isatty(STDERR_FILENO) && !(options->flags & VDECAPTURE_FLAG_QUIET))
		fprintf(stderr, "\n");
	fclose(f);
	vde_close(conn);
	return 0;
err_file:
	vde_close(conn);
err_vde:
	return 1;
}

static char *short_options = "c:s:t:aqh";
static struct option long_options[] = {
	{"count", required_argument, 0,  'c' },
	{"size",  required_argument, 0,  's' },
	{"time",  required_argument, 0,  't' },
	{"quiet", no_argument,       0,  'q' },
	{"append",no_argument,       0,  'a' },
	{"help",  no_argument,       0,  'h' },
	{0,       0,                 0,  0 }
};

static void usage_exit(char *progname) {
	fprintf(stderr, 
			"Usage: %s [OPTIONS] VNL outfile\n"
			"  VNL is the Virtual Network Locator (e.g. hub:///tmp/hub)\n"	
			"    see vde_plug(1)]\n"
			"  outfile is the pathname of the output file (- means stdout)\n\n"
			"OPTIONS:\n"
			"  -c, --count   max number of captured packets\n"
			"  -s, --size    max size of the output file\n"
			"  -t, --time    max capture time\n"
			"  -a, --append  append data if the output file exists\n"
			"  -q, --quiet   do not print packet counter on stderr\n"
			"  -h, --help    display this help and exit\n"
			"\n", progname);
	exit(1);
}

int main(int argc, char *argv[]) {
	static struct options options;
	char *vnl;
	char *outpath;
	while (1) {
		int option_index = 0;
		int c = getopt_long(argc, argv, short_options,
				long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
			case 'c': options.maxcount = strtol(optarg, NULL, 10); break;
			case 's': options.maxlen = strtoll(optarg, NULL, 10); break;
			case 't': options.maxtime = strtol(optarg, NULL, 10); break;
			case 'a': options.flags |= VDECAPTURE_FLAG_APPEND; break;
			case 'q': options.flags |= VDECAPTURE_FLAG_QUIET; break;
			case 'h':
			default: usage_exit(basename(argv[0]));
		}
	}
	if (optind + 2 != argc) 
		usage_exit(basename(argv[0]));
	vnl = argv[optind];
	outpath = argv[optind + 1];
	signal(SIGINT, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGALRM, sighandler);
	signal(SIGHUP, sighandler);
	return mainloop(vnl, outpath, &options);
}
