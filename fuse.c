
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
	for (i = 0; i < dentry->ddent->size; i ++) {
		child = get_nth_dentry(dentry, i);
		if (IS_ERR(child)) {
			err = -PTR_ERR(child);
			goto out;
		}
		if (filldir(filldir_buf, (char *)child->ddent->name, NULL, 0)) {
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
	struct dentry *dentry;

	TRACE("%s\n", path);

	dentry = find_dentry(path);
	if (IS_ERR(dentry))
		return -PTR_ERR(dentry);

	if (S_ISDIR(dentry->ddent->mode)) {
		put_dentry(dentry);
		return -EISDIR;
	}
	if (!S_ISREG(dentry->ddent->mode)) {
		put_dentry(dentry);
		return -EPERM;
	}

	fuse_file->fh = (uint64_t)(uintptr_t)dentry;

	return 0;
}

static int zunkfs_read(const char *path, char *buf, size_t bufsz, off_t offset,
		struct fuse_file_info *fuse_file)
{
	struct chunk_node *cnode;
	struct dentry *dentry;
	unsigned cplen;
	unsigned chunk_nr;
	unsigned chunk_off;
	unsigned chunk_size;
	int len;

	TRACE("path=%p bufsz=%zd offset=%zd\n", path, bufsz, offset);

	dentry = (struct dentry *)(uintptr_t)fuse_file->fh;
	if (!dentry)
		return -EINVAL;

	chunk_nr = offset / CHUNK_SIZE;
	chunk_off = offset % CHUNK_SIZE;

	lock(&dentry->mutex);
	for (len = 0; len < bufsz; ) {
		TRACE("chunk_nr=%u chunk_off=%u\n", chunk_nr, chunk_off);

		if (chunk_nr == dentry->chunk_tree.nr_leafs)
			break;

		chunk_size = CHUNK_SIZE;
		if (chunk_nr == dentry->chunk_tree.nr_leafs-1) {
			chunk_size = dentry->ddent->size % CHUNK_SIZE;
			if (chunk_size <= chunk_off)
				break;
		}

		cnode = get_nth_chunk(&dentry->chunk_tree, chunk_nr);
		if (IS_ERR(cnode)) {
			len = -PTR_ERR(cnode);
			break;
		}

		cplen = chunk_size;
		if (cplen > bufsz - len)
			cplen = bufsz - len;

		memcpy(buf + len, cnode->chunk_data + chunk_off, cplen);
		len += cplen;
		chunk_off += cplen;
		if (chunk_off == CHUNK_SIZE) {
			chunk_off = 0;
			chunk_nr ++;
		}
		put_chunk_node(cnode);
	}
	unlock(&dentry->mutex);

	return len;
}

static int zunkfs_write(const char *path, const char *buf, size_t bufsz,
		off_t offset, struct fuse_file_info *fuse_file)
{
	struct chunk_node *cnode;
	struct dentry *dentry;
	unsigned cplen;
	unsigned chunk_nr;
	unsigned chunk_off;
	int len;

	TRACE("path=%p bufsz=%zd offset=%zd\n", path, bufsz, offset);

	dentry = (struct dentry *)(uintptr_t)fuse_file->fh;
	if (!dentry)
		return -EINVAL;

	chunk_nr = offset / CHUNK_SIZE;
	chunk_off = offset % CHUNK_SIZE;

	/*
	 * Don't allow sparse files.
	 */
	lock(&dentry->mutex);

	len = -EINVAL;
	if (offset > dentry->ddent->size) {
		WARNING("Tried to write at offset %llu (size=%llu)\n",
				offset, dentry->ddent->size);
		goto out;
	}

	for (len = 0; len < bufsz; ) {
		cnode = get_nth_chunk(&dentry->chunk_tree, chunk_nr);
		if (IS_ERR(cnode)) {
			len = -PTR_ERR(cnode);
			break;
		}
		cplen = CHUNK_SIZE - chunk_off;
		if (cplen > bufsz - len)
			cplen = bufsz - len;
		memcpy(cnode->chunk_data + chunk_off, buf + len, cplen);
		len += cplen;
		chunk_off += cplen;
		if (chunk_nr == dentry->chunk_tree.nr_leafs - 1) {
			dentry->ddent->size = chunk_nr * CHUNK_SIZE +
				chunk_off;
		}
		if (chunk_off == CHUNK_SIZE) {
			chunk_off = 0;
			chunk_nr ++;
		}
		put_chunk_node(cnode);
	}

	lock(dentry->ddent_mutex);
	dentry->ddent->mtime = time(NULL);
	dentry->ddent_cnode->dirty = 1;
	unlock(dentry->ddent_mutex);
out:
	unlock(&dentry->mutex);
	return len;
}

static int zunkfs_release(const char *path, struct fuse_file_info *fuse_file)
{
	struct dentry *dentry;

	TRACE("%s\n", path);

	dentry = (struct dentry *)(uintptr_t)fuse_file->fh;
	if (!dentry)
		return -EINVAL;

	put_dentry(dentry);
	return 0;
}

static struct dentry *create_dentry(const char *path, mode_t mode)
{
	struct dentry *dentry;
	struct dentry *parent;
	const char *name;

	dentry = find_dentry_parent(path, &parent, &name);
	if (IS_ERR(dentry))
		return dentry;
	if (dentry) {
		put_dentry(parent);
		put_dentry(dentry);
		return ERR_PTR(EEXIST);
	}
	dentry = add_dentry(parent, name, mode);
	put_dentry(parent);
	return dentry;
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
	struct dentry *dentry;

	TRACE("%s mode=%o\n", path, mode);

	dentry = create_dentry(path, mode | S_IFREG);
	if (IS_ERR(dentry))
		return -PTR_ERR(dentry);

	if (fuse_file)
		fuse_file->fh = (uint64_t)(uintptr_t)dentry;
	else
		put_dentry(dentry);

	return 0;
}

static int zunkfs_flush(const char *path, struct fuse_file_info *fuse_file)
{
	struct dentry *dentry;
	int err;

	TRACE("%s\n", path);

	dentry = (struct dentry *)(uintptr_t)fuse_file->fh;
	if (!dentry)
		return -EINVAL;

	lock(&dentry->mutex);
	err = flush_chunk_tree(&dentry->chunk_tree);
	unlock(&dentry->mutex);

	return err;
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

	zero_chunk_digest(root_ddent.digest);

	err = set_root(&root_ddent, &root_mutex);
	if (err) {
		ERROR("Failed to set root: %s\n", strerror(-err));
		exit(-1);
	}

	return fuse_main(argc, argv, &zunkfs_operations, NULL);
}

