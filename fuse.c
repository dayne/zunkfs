
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

#include "zunkfs.h"

struct disk_dirent {
	unsigned char	d_digest[CHUNK_DIGEST_LEN];
	char		d_name[255];
	mode_t		d_mode;
	off_t		d_size;
	time_t		d_ctime;
	time_t		d_mtime;
};

#define DIRENTS_PER_CHUNK	(CHUNK_SIZE / sizeof(struct disk_dirent))

struct dentry {
	struct disk_dirent	*ddent;
	struct chunk_node	*ddent_cnode;
	struct dentry		*parent;
	unsigned		ref_count;
	struct chunk_tree	chunk_tree;
};

static struct dentry zunkfs_root;
static DECLARE_MUTEX(zunkfs_mutex);

static inline unsigned nr_dentries(const struct dentry *parent)
{
	return parent->ddent->d_size / sizeof(struct disk_dirent);
}

static inline unsigned dentry_nr(const struct dentry *dentry)
{
	return dentry->ddent -
		(struct disk_dirent *)dentry->ddent_cnode->chunk_data;
}

static struct dentry *new_dentry(struct disk_dirent *ddent, 
		struct dentry *parent, struct chunk_node *ddent_cnode)
{
	struct dentry *dentry;
	unsigned nr_chunks;
	int err;

	dentry = malloc(sizeof(struct dentry));
	if (!dentry)
		return NULL;

	dentry->ddent = ddent;
	dentry->parent = parent;
	dentry->ddent_cnode = ddent_cnode;
	dentry->ref_count = 0;

	nr_chunks = (ddent->d_size + CHUNK_SIZE - 1) / CHUNK_SIZE;
	if (!nr_chunks)
		nr_chunks = 1;

	err = init_chunk_tree(&dentry->chunk_tree, nr_chunks, ddent->d_digest);
	if (err < 0) {
		free(dentry);
		errno = -err;
		return NULL;
	}

	parent->ref_count ++;

	ddent_cnode->child[dentry_nr(dentry)] = dentry;

	return dentry;
}

static struct dentry *get_dentry_nr(struct dentry *parent, unsigned nr)
{
	struct dentry *dentry;
	struct disk_dirent *ddent;
	struct chunk_node *cnode;
	unsigned chunk_nr;
	unsigned chunk_off;

	assert(S_ISDIR(parent->ddent->d_mode));

	chunk_nr = nr / DIRENTS_PER_CHUNK;
	chunk_off = nr % DIRENTS_PER_CHUNK;

	cnode = get_chunk_nr(&parent->chunk_tree, chunk_nr);
	if (!cnode)
		return NULL;

	if (cnode->child) {
		dentry = cnode->child[chunk_off];
		if (dentry)
			goto got_dentry;
	}

	cnode->child = calloc(DIRENTS_PER_CHUNK, sizeof(struct dentry *));
	if (!cnode->child)
		goto error;

	ddent = (struct disk_dirent *)cnode->chunk_data + chunk_off;

	if (nr == nr_dentries(parent))
		zero_chunk_digest(ddent->d_digest);

	dentry = new_dentry(ddent, parent, cnode);
	if (!dentry)
		goto error;

got_dentry:
	dentry->ref_count ++;
	return dentry;
error:
	put_chunk_node(cnode);
	return NULL;
}

static struct dentry *lookup1(struct dentry *parent, const char *name, int len)
{
	struct dentry *dentry;
	unsigned nr, count;

	if (!strncmp(name, ".", len)) {
		parent->ref_count ++;
		return parent;
	}

	if (!strncmp(name, "..", len)) {
		dentry = parent->parent ?: parent;
		dentry->ref_count ++;
		return dentry;
	}

	/*
	 * This could be optimized a bit by going directly to
	 * chunks, and accessing disk_dirent structs instead
	 * of full dentries (which have to initailize their
	 * chunk_trees.)
	 *
	 * But what this really needs is a huge algorithmic
	 * change. The linear scan will be dog slow for
	 * large directories.
	 */
	count = nr_dentries(parent);
	for (nr = 0; nr < count; nr ++) {
		dentry = get_dentry_nr(parent, nr);
		if (!dentry)
			return NULL;
		if (strncmp(dentry->ddent->d_name, name, len))
			continue;
		if (!dentry->ddent->d_name[len]) {
			dentry->ref_count ++;
			return dentry;
		}
	}

	errno = ENOENT;
	return NULL;
}

static void free_dentry(struct dentry *dentry)
{
	struct dentry *parent;
	int saved_errno = errno;

	/*
	 * Note that ->ddent_cnode->child will be 
	 * freed by free_chunk_tree().
	 */

	for (;;) {
		parent = dentry->parent;
		assert(parent != NULL);

		free_chunk_tree(&dentry->chunk_tree);
		if (dentry->ddent_cnode)
			put_chunk_node(dentry->ddent_cnode);
		free(dentry);
		if (--parent->ref_count)
			break;
		dentry = parent;
	}

	errno = saved_errno;
}

static inline void put_dentry(struct dentry *dentry)
{
	if (!--dentry->ref_count)
		free_dentry(dentry);
}

static struct dentry *__lookup(const char *path, struct dentry **pparent,
		const char **name)
{
	struct dentry *parent;
	struct dentry *dentry;
	char *next;
	int len;

	TRACE("%s %p %p\n", path, pparent, name);

	parent = NULL;
	dentry = &zunkfs_root;
	dentry->ref_count ++;

	while (S_ISDIR(dentry->ddent->d_mode)) {
		parent = dentry;
		next = strchr(path, '/');
		len = next ? next - path : strlen(path);
		dentry = lookup1(parent, path, len);
		if (!dentry && errno != ENOENT) {
			put_dentry(parent);
			return NULL;
		}
		if (!next) {
			if (pparent)
				*pparent = parent;
			else
				put_dentry(parent);
			if (name)
				*name = path;
			TRACE("found %p\n", dentry);
			return dentry;
		}
		put_dentry(parent);
		if (!dentry)
			return NULL;
		path = next + 1;
	}

	if (next) {
		put_dentry(dentry);
		errno = ENOTDIR;
		return NULL;
	}

	return dentry;
}

static inline struct dentry *lookup(const char *path)
{
	errno = ENOENT;
	return __lookup(path, NULL, NULL);
}

static struct dentry *create_dentry(const char *path, mode_t mode)
{
	struct dentry *parent = NULL;
	struct dentry *dentry;
	const char *name;

	TRACE("%s %o\n", path, mode);

	dentry = __lookup(path, &parent, &name);
	if (dentry) {
		put_dentry(dentry);
		put_dentry(parent);
		errno = EEXIST;
		return NULL;
	}

	assert(parent != NULL);
	assert(name != NULL);

	TRACE("parent=%p name=%p\n", parent, name);

	dentry = get_dentry_nr(parent, nr_dentries(parent));
	if (!dentry) {
		TRACE("get_dentry_nr(%d) failed.\n", nr_dentries(parent));
		put_dentry(parent);
		return NULL;
	}

	parent->ddent->d_size += sizeof(struct disk_dirent);
	parent->ddent->d_mtime = time(NULL);
	parent->ddent_cnode->dirty = 1;
	put_dentry(parent);

	strcpy(dentry->ddent->d_name, name);
	dentry->ddent->d_mode = mode;
	dentry->ddent->d_size = 0;
	dentry->ddent->d_ctime = time(NULL);
	dentry->ddent->d_mtime = dentry->ddent->d_ctime;

	dentry->ddent_cnode->dirty = 1;

	TRACE("new dentry: %p\n", dentry);

	return dentry;
}

static int zunkfs_getattr(const char *path, struct stat *stbuf)
{
	struct dentry *dentry;
	struct disk_dirent *ddent;

	TRACE("%s\n", path);

	lock_mutex(&zunkfs_mutex);
	dentry = lookup(path);
	if (!dentry) {
		unlock_mutex(&zunkfs_mutex);
		return -errno;
	}

	memset(stbuf, 0, sizeof(struct stat));

	ddent = dentry->ddent;

	stbuf->st_ino = ddent->d_ctime;
	stbuf->st_mode = ddent->d_mode;
	stbuf->st_nlink = 1;
	stbuf->st_uid = getuid();
	stbuf->st_gid = getgid();
	stbuf->st_size = ddent->d_size;
	stbuf->st_atime = ddent->d_mtime;
	stbuf->st_mtime = ddent->d_mtime;
	stbuf->st_ctime = ddent->d_ctime;

	put_dentry(dentry);
	unlock_mutex(&zunkfs_mutex);

	return 0;
}

static int zunkfs_readdir(const char *path, void *filldir_buf,
		fuse_fill_dir_t filldir, off_t offset,
		struct fuse_file_info *fuse_file)
{
	struct dentry *dentry;
	struct dentry *child;
	unsigned i, count;

	TRACE("%s\n", path);

	lock_mutex(&zunkfs_mutex);
	dentry = lookup(path);
	if (!dentry) {
		unlock_mutex(&zunkfs_mutex);
		return -errno;
	}
	if (!S_ISDIR(dentry->ddent->d_mode)) {
		put_dentry(dentry);
		unlock_mutex(&zunkfs_mutex);
		return -ENOTDIR;
	}

	if (filldir(filldir_buf, ".", NULL, 0) ||
			filldir(filldir_buf, "..", NULL, 0)) {
		put_dentry(dentry);
		unlock_mutex(&zunkfs_mutex);
		return -ENOBUFS;
	}

	count = nr_dentries(dentry);
	for (i = 0; i < count; i ++) {
		child = get_dentry_nr(dentry, i);
		if (!child) {
			put_dentry(dentry);
			unlock_mutex(&zunkfs_mutex);
			return -errno;
		}
		if (filldir(filldir_buf, child->ddent->d_name, NULL, 0)) {
			put_dentry(child);
			put_dentry(dentry);
			unlock_mutex(&zunkfs_mutex);
			return -ENOBUFS;
		}
		put_dentry(child);
	}
	put_dentry(dentry);
	unlock_mutex(&zunkfs_mutex);
	return 0;
}

static int zunkfs_open(const char *path, struct fuse_file_info *fuse_file)
{
	struct dentry *dentry;

	TRACE("%s\n", path);

	lock_mutex(&zunkfs_mutex);
	dentry = lookup(path);
	if (!dentry) {
		unlock_mutex(&zunkfs_mutex);
		return -ENOENT;
	}

	if (S_ISDIR(dentry->ddent->d_mode)) {
		put_dentry(dentry);
		unlock_mutex(&zunkfs_mutex);
		return -EISDIR;
	}
	if (!S_ISREG(dentry->ddent->d_mode)) {
		put_dentry(dentry);
		unlock_mutex(&zunkfs_mutex);
		return -EPERM;
	}

	fuse_file->fh = (uint64_t)(uintptr_t)dentry;
	unlock_mutex(&zunkfs_mutex);

	return 0;
}

static int zunkfs_read(const char *path, char *buf, size_t bufsz, off_t offset,
		struct fuse_file_info *fuse_file)
{
	struct chunk_node *cnode;
	struct dentry *dentry;
	unsigned cplen, len;
	unsigned chunk_nr;
	unsigned chunk_off;
	unsigned chunk_size;

	TRACE("path=%p bufsz=%zd offset=%zd\n", path, bufsz, offset);

	dentry = (struct dentry *)(uintptr_t)fuse_file->fh;
	if (!dentry)
		return -EINVAL;

	chunk_nr = offset / CHUNK_SIZE;
	chunk_off = offset % CHUNK_SIZE;

	lock_mutex(&zunkfs_mutex);
	for (len = 0; len < bufsz; ) {
		TRACE("chunk_nr=%u chunk_off=%u\n", chunk_nr, chunk_off);

		if (chunk_nr == dentry->chunk_tree.nr_chunks)
			break;

		chunk_size = CHUNK_SIZE;
		if (chunk_nr == dentry->chunk_tree.nr_chunks-1) {
			chunk_size = dentry->ddent->d_size % CHUNK_SIZE;
			if (chunk_size <= chunk_off)
				break;
		}

		cnode = get_chunk_nr(&dentry->chunk_tree, chunk_nr);
		if (!cnode) {
			unlock_mutex(&zunkfs_mutex);
			return -errno;
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
	unlock_mutex(&zunkfs_mutex);

	return len;
}

static int zunkfs_write(const char *path, const char *buf, size_t bufsz,
		off_t offset, struct fuse_file_info *fuse_file)
{
	struct chunk_node *cnode;
	struct dentry *dentry;
	unsigned cplen, len;
	unsigned chunk_nr;
	unsigned chunk_off;

	TRACE("path=%p bufsz=%zd offset=%zd\n", path, bufsz, offset);

	dentry = (struct dentry *)(uintptr_t)fuse_file->fh;
	if (!dentry)
		return -EINVAL;

	/*
	 * Don't allow sparse files.
	 */
	lock_mutex(&zunkfs_mutex);
	if (offset > dentry->ddent->d_size) {
		WARNING("Tried to write at offset %llu (size=%llu)\n",
				offset, dentry->ddent->d_size);
		unlock_mutex(&zunkfs_mutex);
		return -EINVAL;
	}

	chunk_nr = offset / CHUNK_SIZE;
	chunk_off = offset % CHUNK_SIZE;

	for (len = 0; len < bufsz; ) {
		cnode = get_chunk_nr(&dentry->chunk_tree, chunk_nr);
		if (!cnode) {
			lock_mutex(&zunkfs_mutex);
			return -errno;
		}
		cplen = CHUNK_SIZE - chunk_off;
		if (cplen > bufsz - len)
			cplen = bufsz - len;
		memcpy(cnode->chunk_data + chunk_off, buf + len, cplen);
		len += cplen;
		chunk_off += cplen;
		if (chunk_nr == dentry->chunk_tree.nr_chunks - 1) {
			dentry->ddent->d_size = chunk_nr * CHUNK_SIZE +
				chunk_off;
		}
		if (chunk_off == CHUNK_SIZE) {
			chunk_off = 0;
			chunk_nr ++;
		}
		put_chunk_node(cnode);
	}

	dentry->ddent->d_mtime = time(NULL);
	dentry->ddent_cnode->dirty = 1;
	unlock_mutex(&zunkfs_mutex);

	return len;
}

static int zunkfs_release(const char *path, struct fuse_file_info *fuse_file)
{
	struct dentry *dentry;

	TRACE("%s\n", path);

	dentry = (struct dentry *)(uintptr_t)fuse_file->fh;
	if (!dentry)
		return -EINVAL;

	lock_mutex(&zunkfs_mutex);
	put_dentry(dentry);
	unlock_mutex(&zunkfs_mutex);
	return 0;
}

static int zunkfs_mkdir(const char *path, mode_t mode)
{
	struct dentry *dentry;

	TRACE("%s %o\n", path, mode);

	lock_mutex(&zunkfs_mutex);
	dentry = create_dentry(path, mode | S_IFDIR);
	if (!dentry) {
		unlock_mutex(&zunkfs_mutex);
		return -errno;
	}
	put_dentry(dentry);
	unlock_mutex(&zunkfs_mutex);
	return 0;
}

static int zunkfs_create(const char *path, mode_t mode,
		struct fuse_file_info *fuse_file)
{
	struct dentry *dentry;

	TRACE("%s mode=%o\n", path, mode);

	lock_mutex(&zunkfs_mutex);
	dentry = create_dentry(path, mode | S_IFREG);
	if (!dentry) {
		unlock_mutex(&zunkfs_mutex);
		return -errno;
	}

	if (fuse_file)
		fuse_file->fh = (uint64_t)(uintptr_t)dentry;
	else
		put_dentry(dentry);

	unlock_mutex(&zunkfs_mutex);

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

	lock_mutex(&zunkfs_mutex);
	err = flush_chunk_tree(&dentry->chunk_tree);
	unlock_mutex(&zunkfs_mutex);

	return err;
}

static int zunkfs_unlink(const char *path)
{
	struct dentry *parent;
	struct dentry *dentry;
	struct dentry *replacement;
	struct disk_dirent *tmp_ddent;
	struct chunk_node *tmp_cnode;

	TRACE("%s\n", path);

	lock_mutex(&zunkfs_mutex);
	dentry = lookup(path);
	if (!dentry) {
		unlock_mutex(&zunkfs_mutex);
		return -errno;
	}

	parent = dentry->parent;
	if (nr_dentries(parent) > 1) {
		replacement = get_dentry_nr(parent, nr_dentries(parent) - 1);
		if (!replacement) {
			put_dentry(dentry);
			unlock_mutex(&zunkfs_mutex);
			return -errno;
		}

		memcpy(dentry->ddent, replacement->ddent,
				sizeof(struct disk_dirent));

		tmp_ddent = replacement->ddent;
		replacement->ddent = dentry->ddent;
		dentry->ddent = tmp_ddent;

		tmp_cnode = replacement->ddent_cnode;
		replacement->ddent_cnode = dentry->ddent_cnode;
		dentry->ddent_cnode = tmp_cnode;

		replacement->ddent_cnode->child[dentry_nr(replacement)] =
			replacement;

	}

	dentry->ddent_cnode->child[dentry_nr(dentry)] = NULL;
	memset(dentry->ddent, 0, sizeof(struct disk_dirent));
	dentry->ddent_cnode->dirty = 1;

	put_dentry(dentry);

	parent->ddent->d_size -= sizeof(struct disk_dirent);
	parent->ddent->d_mtime = time(NULL);
	parent->ddent_cnode->dirty = 1;
	put_dentry(parent);
	unlock_mutex(&zunkfs_mutex);

	return 0;
}

static int zunkfs_utimens(const char *path, const struct timespec tv[2])
{
	struct dentry *dentry;

	TRACE("%s\n", path);

	lock_mutex(&zunkfs_mutex);
	dentry = lookup(path);
	if (!dentry) {
		unlock_mutex(&zunkfs_mutex);
		return -errno;
	}

	if (tv[1].tv_sec != dentry->ddent->d_mtime) {
		dentry->ddent->d_mtime = tv[1].tv_sec;
		dentry->ddent_cnode->dirty = 1;
	}
	put_dentry(dentry);
	unlock_mutex(&zunkfs_mutex);

	return 0;
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
	.utimens	= zunkfs_utimens
};

FILE *zunkfs_log_fd = NULL;

int main(int argc, char **argv)
{
	struct disk_dirent root_ddent;
	struct chunk_node root_cnode;
	char *log_file;

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

	zunkfs_root.ddent = &root_ddent;
	zunkfs_root.ddent_cnode = &root_cnode;
	zunkfs_root.parent = NULL;
	zunkfs_root.ref_count = 1;

	strcpy(root_ddent.d_name, "/");
	root_ddent.d_mode = S_IFDIR | S_IRWXU;
	root_ddent.d_size = 0;
	root_ddent.d_ctime = time(NULL);
	root_ddent.d_mtime = time(NULL);

	memset(root_cnode.chunk_data, 0, CHUNK_SIZE);
	root_cnode.chunk_digest = root_ddent.d_digest;
	root_cnode.parent = NULL;
	root_cnode.dirty = 0;
	root_cnode.ref_count = 1;
	root_cnode.child = NULL;

	zero_chunk_digest(root_ddent.d_digest);
	init_chunk_tree(&zunkfs_root.chunk_tree, 1, root_ddent.d_digest);

	return fuse_main(argc, argv, &zunkfs_operations, NULL);
}

void __zprintf(char level, const char *function, int line, const char *fmt, ...)
{
	static DECLARE_MUTEX(log_mutex);
	const char *level_str = NULL;
	va_list ap;

	if (level == 'W')
		level_str = "WARN: ";
	else if (level == 'E')
		level_str = "ERR:  ";
	else if (level == 'T')
		level_str = "TRACE:";
	else
		abort();

	lock_mutex(&log_mutex);
	fprintf(zunkfs_log_fd, "%lx %s %s:%d: ",
			((unsigned long)pthread_self()) >> 8,
			level_str, function, line);

	va_start(ap, fmt);
	vfprintf(zunkfs_log_fd, fmt, ap);
	va_end(ap);

	fflush(zunkfs_log_fd);

	unlock_mutex(&log_mutex);
}

