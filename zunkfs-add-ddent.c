
#define _GNU_SOURCE

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <inttypes.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "zunkfs.h"
#include "chunk-db.h"
#include "dir.h"
#include "digest.h"
#include "utils.h"

static const char *prog;

static int write_dentry(int fd, struct disk_dentry *de)
{
	void *ptr = de;
	int len;

	for (len = 0; len < sizeof(struct disk_dentry); ) {
		int n = write(fd, ptr + len, sizeof(struct disk_dentry) - len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		len += n;
	}

	return len;
}

static inline int str2digest(const char *str, unsigned char *digest)
{
	unsigned char *d;

	d = __string_digest(str, digest);
	if (IS_ERR(d))
		return PTR_ERR(d);

	return 0;
}

enum {
	OPT_HELP = 'h',
	OPT_CHUNK_DB = 'd',
	OPT_LOG = 'l',
};

static const char short_opts[] = {
	OPT_HELP,
	OPT_CHUNK_DB,
	OPT_LOG,
	0
};

static const struct option long_opts[] = {
	{ "help", no_argument, NULL, OPT_HELP },
	{ "chunk-db", required_argument, NULL, OPT_CHUNK_DB },
	{ "log", required_argument, NULL, OPT_LOG },
	{ NULL }
};

#define USAGE \
"<file|dir> <digest> <secret digest> <size> <name>\n"\
"-h|--help\n"\
"-d|--chunk-db <spec>\n"\
"-l|--log [<E|W|T>,]<file|stderr|stdout>\n"

static void usage(int exit_code)
{
	fprintf(stderr, "Usage: %s [options] %s\n", prog, USAGE);
	exit(exit_code);
}

static void proc_opt(int opt, char *arg)
{
	int err;

	switch(opt) {
	case OPT_HELP:
		usage(0);
	case OPT_CHUNK_DB:
		if (!strncmp(arg, "ro,", 3))
			err = add_chunkdb(CHUNKDB_RO, arg + 3);
		else if (!strncmp(arg, "rw,wt,", 6))
			err = add_chunkdb(CHUNKDB_RW|CHUNKDB_WT, arg + 6);
		else if (!strncmp(arg, "rw,", 3))
			err = add_chunkdb(CHUNKDB_RW, arg + 3);
		else {
			fprintf(stderr, "Invalid db spec: %s\n", arg);
			exit(-1);
		}
		if (err) {
			fprintf(stderr, "Failed to add chunk db %s: %s\n", arg,
					strerror(-err));
			exit(-2);
		}
		break;
	case OPT_LOG:
		if (zunkfs_log_fd) {
			fprintf(stderr, "Log file specified more than once.\n");
			exit(-1);
		}
		if (arg[1] == ',') {
			if (!strchr("EWT", arg[0])) {
				fprintf(stderr, "Invalid log level.\n");
				exit(-1);
			}
			zunkfs_log_level = arg[0];
			arg += 2;
		}
		if (!strcmp(arg, "stderr"))
			zunkfs_log_fd = stderr;
		else if (!strcmp(arg, "stdout"))
			zunkfs_log_fd = stdout;
		else
			zunkfs_log_fd = fopen(arg, "w");
		break;
	default:
		usage(-1);
	}
}

int main(int argc, char **argv)
{
	char cwd[1024];
	int i, fd, err, opt;
	struct disk_dentry new_ddent;

	prog = basename(argv[0]);

	getcwd(cwd, 1024);

	while ((opt = getopt_long(argc, argv, short_opts, long_opts, NULL))
			!= -1)
		proc_opt(opt, optarg);

	i = optind;
	if (argc - i != 5)
		usage(-1);

	memset(&new_ddent, 0, sizeof(struct disk_dentry));

	/*
	 * XXX: What happens if the new ddent points to a parent dir's ddent?
	 */
	if (!strcmp(argv[i], "file"))
		new_ddent.mode = S_IFREG | S_IRUSR | S_IWUSR;
	else if (!strcmp(argv[i], "dir"))
		new_ddent.mode = S_IFDIR | S_IRWXU;
	else {
		fprintf(stderr, "Please specify file or directory\n\n");
		usage(-1);
	}

	if (str2digest(argv[++i], new_ddent.digest)) {
		fprintf(stderr, "Invalid digest: %s\n\n", argv[i]);
		usage(-1);
	}
	if (str2digest(argv[++i], new_ddent.secret_digest)) {
		fprintf(stderr, "Invalid secret digest: %s\n\n", argv[i]);
		usage(-1);
	}

	new_ddent.size = atoll(argv[++i]);
	if (!new_ddent.size) {
		fprintf(stderr, "Invalid size: %"PRIu64"\n\n", new_ddent.size);
		usage(-1);
	}

	if (snprintf((char*)new_ddent.name, DDENT_NAME_MAX, "%s", argv[++i]) >=
			DDENT_NAME_MAX) {
		fprintf(stderr, "Name too long: %s\n\n", argv[i]);
		usage(-1);
	}
	
	fd = open(DIR_AS_FILE, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open %s/%s: %s\n", cwd, DIR_AS_FILE, 
				strerror(errno));
		exit(-2);
	}

	err = write_dentry(fd, &new_ddent);
	if (err < 0) {
		fprintf(stderr, "Filed to add ddent: %s\n", strerror(-err));
		exit(-3);
	}

	close(fd);
	return 0;
}
