
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "zunkfs.h"
#include "chunk-db.h"
#include "dir.h"

static int read_dentry(int fd, struct disk_dentry *de)
{
	void *ptr = de;
	int len;

	for (len = 0; len < sizeof(struct disk_dentry); ) {
		int n = read(fd, ptr + len, sizeof(struct disk_dentry) - len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!n)
			break;
		len += n;
	}

	return len;
}

int main(int argc, char **argv)
{
	char cwd[1024];
	int i, fd, err;

	getcwd(cwd, 1024);

	for (i = 1; i < argc; i ++) {
		const char *arg = argv[i];
		if (!strncmp(arg, "--chunk-db=", 11)) {
			arg += 11;
			if (!strncmp(arg, "ro,", 3))
				err = add_chunkdb(CHUNKDB_RO, arg + 3);
			else if (!strncmp(arg, "rw,", 3))
				err = add_chunkdb(CHUNKDB_RW, arg + 3);
			else {
				fprintf(stderr, "Invalid db spec: %s\n", arg);
				exit(-1);
			}
		} else if (!strncmp(arg, "--log=", 6)) {
			arg += 6;
			if (zunkfs_log_fd) {
				fprintf(stderr, "Log file specified more "
						"than once\n");
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
		} else {
			fprintf(stderr, "Invalid option: %s\n", arg);
			exit(-1);
		}
	}

	fd = open(SUPER_SECRET_FILE, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open %s/%s: %s\n", cwd, SUPER_SECRET_FILE, 
				strerror(errno));
		exit(-2);
	}

	for (;;) {
		struct disk_dentry dentry;
		int err = read_dentry(fd, &dentry);
		if (err < 0) {
			fprintf(stderr, "read_dentry: %s\n", strerror(errno));
			exit(-3);
		}
		if (!err)
			break;
		printf("%s %s 0%o %llu %u %u %s\n",
				digest_string(dentry.digest),
				digest_string(dentry.secret_digest),
				dentry.mode,
				dentry.size,
				dentry.ctime,
				dentry.mtime,
				dentry.name);
	}

	close(fd);
	return 0;
}
