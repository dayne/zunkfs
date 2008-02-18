
#define FUSE_USE_VERSION	26
#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <pthread.h>
#include <ctype.h>
#include <stdarg.h>
#include <pthread.h>

#include "zunkfs.h"

static int zunkfs_getattr(const char *path, struct stat *stbuf)
{
	struct dentry *dentry;
	struct disk_dentry *ddent;

	TRACE("%s\n", path);

	dentry = find_dentry(path);
	if (IS_ERR(dentry))
		return -PTR_ERR(dentry);

	memset(stbuf, 0, sizeof(struct stat));

	ddent = dentry->ddent;

	lock(dentry->ddent_mutex);

	stbuf->st_ino = ddent->ctime;
	stbuf->st_mode = ddent->mode;
	stbuf->st_nlink = 1;
	stbuf->st_uid = getuid();
	stbuf->st_gid = getgid();
	stbuf->st_size = ddent->size;
	stbuf->st_atime = ddent->mtime;
	stbuf->st_mtime = ddent->mtime;
	stbuf->st_ctime = ddent->ctime;

	unlock(dentry->ddent_mutex);
	put_dentry(dentry);

	return 0;
}

static int zunkfs_readdir(const char *path, void *filldir_buf,
		fuse_fill_dir_t filldir, off_t offset,
		struct fuse_file_info *fuse_file)
{
	struct dentry *dentry;
	struct dentry *child;
	unsigned i;
	int err;

	TRACE("%s\n", path);

	dentry = find_dentry(path);
	if (IS_ERR(dentry))
		return -PTR_ERR(dentry);

	err = -ENOTDIR;
	if (!S_ISDIR(dentry->ddent->mode))
		goto out;

	err = -ENOBUFS;
	if (filldir(filldir_buf, ".", NULL, 0) ||
			filldir(filldir_buf, "..", NULL, 0))
		goto out;

	/* racy, but should be OK */
	for (i = 0; ; i ++) {
		child = get_nth_dentry(dentry, i);
		if (IS_ERR(child)) {
			err = -PTR_ERR(child);
			if (err == -ENOENT)
				err = 0;
			goto out;
		}
		if (filldir(filldir_buf, (char *)child->ddent->name, NULL, 0)) {
			err = -ENOBUFS;
			put_dentry(child);
			goto out;
		}
		put_dentry(child);
	}
out:
	put_dentry(dentry);
	return err;
}

static int zunkfs_open(const char *path, struct fuse_file_info *fuse_file)
{
	struct open_file *ofile;

	TRACE("%s\n", path);

	ofile = open_file(path);
	if (IS_ERR(ofile))
		return -PTR_ERR(ofile);

	fuse_file->fh = (uint64_t)(uintptr_t)ofile;

	return 0;
}

static int zunkfs_read(const char *path, char *buf, size_t bufsz, off_t offset,
		struct fuse_file_info *fuse_file)
{
	struct open_file *ofile;

	TRACE("path=%p bufsz=%zd offset=%zd\n", path, bufsz, offset);

	ofile = (struct open_file *)(uintptr_t)fuse_file->fh;
	if (!ofile)
		return -EINVAL;

	return read_file(ofile, buf, bufsz, offset);
}

static int zunkfs_write(const char *path, const char *buf, size_t bufsz,
		off_t offset, struct fuse_file_info *fuse_file)
{
	struct open_file *ofile;

	TRACE("path=%p bufsz=%zd offset=%zd\n", path, bufsz, offset);

	ofile = (struct open_file *)(uintptr_t)fuse_file->fh;
	if (!ofile)
		return -EINVAL;

	return write_file(ofile, buf, bufsz, offset);
}

static int zunkfs_release(const char *path, struct fuse_file_info *fuse_file)
{
	struct open_file *ofile;

	TRACE("%s\n", path);

	ofile = (struct open_file *)(uintptr_t)fuse_file->fh;
	if (!ofile)
		return -EINVAL;

	fuse_file->fh = 0;
	return close_file(ofile);
}

static int zunkfs_mkdir(const char *path, mode_t mode)
{
	struct dentry *dentry;

	TRACE("%s %o\n", path, mode);

	dentry = create_dentry(path, mode | S_IFDIR);
	if (IS_ERR(dentry))
		return -PTR_ERR(dentry);
	put_dentry(dentry);
	return 0;
}

static int zunkfs_create(const char *path, mode_t mode,
		struct fuse_file_info *fuse_file)
{
	struct open_file *ofile;

	TRACE("%s mode=%o\n", path, mode);

	ofile = create_file(path, mode);
	if (IS_ERR(ofile))
		return -PTR_ERR(ofile);

	if (fuse_file)
		fuse_file->fh = (uint64_t)(uintptr_t)ofile;
	else
		close_file(ofile);

	return 0;
}

static int zunkfs_flush(const char *path, struct fuse_file_info *fuse_file)
{
	struct open_file *ofile;

	TRACE("%s\n", path);

	ofile = (struct open_file *)(uintptr_t)fuse_file->fh;
	if (!ofile)
		return -EINVAL;

	return flush_file(ofile);
}

static int zunkfs_unlink(const char *path)
{
	struct dentry *dentry;
	int err;

	TRACE("%s\n", path);

	dentry = find_dentry(path);
	err = -PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
		err = del_dentry(dentry);
		put_dentry(dentry);
	}

	return err;
}

static struct fuse_operations zunkfs_operations = {
	.getattr	= zunkfs_getattr,
	.readdir	= zunkfs_readdir,
	.open		= zunkfs_open,
	.read		= zunkfs_read,
	.write		= zunkfs_write,
	.release	= zunkfs_release,
	.mkdir		= zunkfs_mkdir,
	.create		= zunkfs_create,
	.flush		= zunkfs_flush,
	.unlink		= zunkfs_unlink,
};

int main(int argc, char **argv)
{
	struct disk_dentry root_ddent;
	DECLARE_MUTEX(root_mutex);
	char *log_file;
	int err;

	log_file = getenv("ZUNKFS_LOG");
	if (log_file) {
		if (!strcmp(log_file, "stderr"))
			zunkfs_log_fd = stderr;
		else if (!strcmp(log_file, "stdout"))
			zunkfs_log_fd = stdout;
		else
			zunkfs_log_fd = fopen(log_file, "w");
	}

	// FIXME: smarter root?

	namcpy(root_ddent.name, "/");
	root_ddent.mode = S_IFDIR | S_IRWXU;
	root_ddent.size = 0;
	root_ddent.ctime = time(NULL);
	root_ddent.mtime = time(NULL);

	err = random_chunk_digest(root_ddent.secret_digest);
	if (err < 0) {
		ERROR("random_chunk_digest: %s\n", strerror(-err));
		exit(-1);
	}

	memcpy(root_ddent.digest, root_ddent.secret_digest, CHUNK_DIGEST_LEN);

	err = set_root(&root_ddent, &root_mutex);
	if (err) {
		ERROR("Failed to set root: %s\n", strerror(-err));
		exit(-1);
	}

	return fuse_main(argc, argv, &zunkfs_operations, NULL);
}

