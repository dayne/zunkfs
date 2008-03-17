
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "zunkfs.h"
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
	int fd;

	getcwd(cwd, 1024);

	if (argc > 1) {
		fprintf(stderr, "Usage: %s\n", basename(argv[0]));
		exit(-1);
	}

	fd = open(".super_secret_file", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open %s: %s\n", cwd, strerror(errno));
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
