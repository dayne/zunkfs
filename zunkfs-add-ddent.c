
#define _GNU_SOURCE

#include <assert.h>
#include <ctype.h>
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

static int str2digest(const char *str, unsigned char *digest)
{
	static const char digits[] = "0123456789abcdef";
	const char *ptr, *d0, *d1;
	int i;

	if (strlen(str) != CHUNK_DIGEST_STRLEN)
		return -EINVAL;

	memset(digest, 0, CHUNK_DIGEST_LEN);

	for (ptr = str, i = 0; *ptr; i ++) {
		d0 = strchr(digits, tolower(*ptr++));
		d1 = strchr(digits, tolower(*ptr++));
		if (!d0 || !d1)
			return -EINVAL;
		digest[i] = (d0 - digits) | ((d1 - digits) << 4);
	}

	assert(!strcasecmp(str, digest_string(digest)));

	return 0;
}

int main(int argc, char **argv)
{
	char cwd[1024];
	int i, fd, err;
	struct disk_dentry new_ddent;

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
		} else if (!strcmp(arg, "--help")) {
usage:
			fprintf(stderr, "Usage: %s <file|dir> <chunk digest> "
					"<secret digest> <size> <name>\n",
					basename(argv[0]));
			exit(0);
		} else if (arg[0] == '-' && arg[1] != '\0') {
			fprintf(stderr, "Invalid option: %s\n", arg);
			exit(-1);
		} else {
			break;
		}
	}

	if (argc - i != 5)
		goto usage;

	memset(&new_ddent, 0, sizeof(struct disk_dentry));

	/*
	 * XXX: What happens if the new ddent points to a parent dir's ddent?
	 */
	if (!strcmp(argv[i], "file"))
		new_ddent.mode = S_IFREG | S_IRUSR | S_IWUSR;
	else if (!strcmp(argv[i], "dir"))
		new_ddent.mode = S_IFDIR | S_IRWXU;
	else
		goto usage;

	if (str2digest(argv[++i], new_ddent.digest))
		goto usage;
	if (str2digest(argv[++i], new_ddent.secret_digest))
		goto usage;

	new_ddent.size = atoll(argv[++i]);
	if (!new_ddent.size)
		goto usage;

	if (snprintf((char*)new_ddent.name, DDENT_NAME_MAX, "%s", argv[++i]) >=
			DDENT_NAME_MAX) {
		fprintf(stderr, "Name too long.\n");
		goto usage;
	}
	
	fd = open(SUPER_SECRET_FILE, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open %s/%s: %s\n", cwd, SUPER_SECRET_FILE, 
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
