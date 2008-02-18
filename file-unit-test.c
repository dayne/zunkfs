
#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "zunkfs.h"
#include "zunkfs-tests.h"

#define panic(x...) do { \
	fprintf(stderr, "PANIC: " x); \
	abort(); \
} while(0)

static const char spaces[] = "                                                                                                                                                               ";
#define indent_start (spaces + sizeof(spaces) - 1)

int main(int argc, char **argv)
{
	struct disk_dentry root_ddent;
	DECLARE_MUTEX(root_mutex);
	loff_t offset;
	int fd, err;

	struct open_file *ofile;

	zunkfs_log_fd = stdout;

	err = init_disk_dentry(&root_ddent);
	if (err < 0)
		panic("init_disk_dentry: %s\n", strerror(-err));

	namcpy(root_ddent.name, "/");

	root_ddent.mode = S_IFDIR | S_IRWXU;
	root_ddent.size = 0;
	root_ddent.ctime = time(NULL);
	root_ddent.mtime = time(NULL);

	err = set_root(&root_ddent, &root_mutex);
	if (err)
		panic("set_root: %s\n", strerror(-err));

	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		panic("open %s: %s\n", argv[1], strerror(errno));

	fprintf(stderr, "importing %s\n", argv[1]);

	ofile = create_file(basename(argv[1]), 0700);
	if (IS_ERR(ofile))
		panic("create_file: %s\n", strerror(PTR_ERR(ofile)));

	for (offset = 0;;) {
		char buf[4096];
		int n, m;
read_again:
		n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			if (errno != EINTR)
				panic("read %s: %s\n", argv[1], strerror(errno));
			goto read_again;
		}
		if (!n)
			break;

write_again:
		m = write_file(ofile, buf, n, offset);
		if (m < 0) {
			if (errno != EINTR)
				panic("write: %s\n", strerror(-m));
			goto write_again;
		}

		assert(m == n);
		offset += m;
	}

	err = flush_file(ofile);
	if (err < 0)
		panic("flush_file: %s\n", strerror(-err));

	err = close_file(ofile);
	if (err < 0)
		panic("close_file: %s\n", strerror(-err));

	ofile = open_file(basename(argv[1]));
	if (IS_ERR(ofile))
		panic("open_file: %s\n", strerror(-err));

	fprintf(stderr, "verifying...\n");
	err = lseek(fd, 0, SEEK_SET);
	assert(err == 0);
	for (offset = 0;;) {
		char buf[4096];
		char buf2[4096];
		int n, m;

		memset(buf, 0, sizeof(buf));
		memset(buf2, 0, sizeof(buf2));
read_again2:
		n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			if (errno != EINTR)
				panic("read %s: %s\n", argv[1], strerror(errno));
			goto read_again2;
		}
		if (!n)
			break;

read_again3:
		m = read_file(ofile, buf2, n, offset);
		if (m < 0) {
			if (errno != EINTR)
				panic("write: %s\n", strerror(-m));
			goto read_again3;
		}

		assert(m == n);
		assert(!memcmp(buf, buf2, n));
		offset += m;
	}

	printf("size=%llu nr_leafs=%u height=%u\n",
			ofile->dentry->ddent->size,
			ofile->dentry->chunk_tree.nr_leafs,
			ofile->dentry->chunk_tree.height);

	err = close_file(ofile);
	if (err < 0)
		panic("close_file: %s\n", strerror(-err));

	return 0;
}


