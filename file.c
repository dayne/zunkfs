
#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "zunkfs.h"

#define lock_file(of)  lock(&(of)->dentry->mutex)
#define unlock_file(of)  unlock(&(of)->dentry->mutex)

#define lock_file_metadata(of) lock((of)->dentry->ddent_mutex)
#define unlock_file_metadata(of) unlock((of)->dentry->ddent_mutex)

static struct open_file *open_file_dentry(struct dentry *dentry)
{
	struct open_file *ofile;

	if (S_ISDIR(dentry->ddent->mode))
		return ERR_PTR(EISDIR);
	if (!S_ISREG(dentry->ddent->mode))
		return ERR_PTR(EPERM);

	ofile = calloc(1, sizeof(struct open_file));
	if (!ofile)
		return ERR_PTR(ENOMEM);
	ofile->dentry = dentry;
	return ofile;
}

struct open_file *open_file(const char *path)
{
	struct dentry *dentry;
	struct open_file *ofile;

	dentry = find_dentry(path);
	if (IS_ERR(dentry))
		return (void *)dentry;

	ofile = open_file_dentry(dentry);
	if (IS_ERR(ofile))
		put_dentry(dentry);

	return ofile;
}

struct open_file *create_file(const char *path, mode_t mode)
{
	struct dentry *dentry;
	struct open_file *ofile;

	dentry = create_dentry(path, mode | S_IFREG);
	if (IS_ERR(dentry))
		return (void *)dentry;

	ofile = open_file_dentry(dentry);
	if (IS_ERR(ofile))
		put_dentry(dentry);

	return ofile;
}

int close_file(struct open_file *ofile)
{
	unsigned i, retv = 0;

	lock_file(ofile);
	for (i = 0; i < FILE_CHUNK_CACHE_SIZE; i ++) {
		if (!ofile->ccache[i])
			break;
		put_chunk_node(ofile->ccache[i]);
		ofile->ccache[i] = NULL;
	}
	if (ofile->dentry->chunk_tree.root)
		retv = flush_chunk_tree(&ofile->dentry->chunk_tree);
	unlock_file(ofile);

	put_dentry(ofile->dentry);

	memset(ofile, 0xcc, sizeof(struct open_file));
	free(ofile);

	return retv;
}

int flush_file(struct open_file *ofile)
{
	unsigned i, retv = 0;

	lock_file(ofile);
	for (i = 0; i < FILE_CHUNK_CACHE_SIZE; i ++) {
		if (!ofile->ccache[i])
			break;
		put_chunk_node(ofile->ccache[i]);
		ofile->ccache[i] = NULL;
	}
	if (ofile->dentry->chunk_tree.root)
		retv = flush_chunk_tree(&ofile->dentry->chunk_tree);
	unlock_file(ofile);

	return retv;
}

static void cache_file_chunk(struct open_file *ofile, struct chunk_node *cnode)
{
	unsigned index;

	assert(have_mutex(&ofile->dentry->mutex));

	index = ofile->ccache_index++ % FILE_CHUNK_CACHE_SIZE;
	if (ofile->ccache[index])
		put_chunk_node(ofile->ccache[index]);
	ofile->ccache[index] = cnode;
}

static int rw_file(struct open_file *ofile, char *buf, size_t bufsz,
		off_t offset, int read)
{
	struct chunk_node *cnode;
	unsigned chunk_nr;
	unsigned chunk_off;
	uint64_t file_size;
	int len, cplen;

	file_size = ofile->dentry->size;
	if (offset > file_size)
		return -EINVAL;
	if (read && offset == file_size)
		return 0;
	if (bufsz > INT_MAX)
		return -EINVAL;
	if (read && (bufsz + offset) > file_size)
		bufsz = file_size - offset;

	chunk_nr = offset / CHUNK_SIZE;
	chunk_off = offset % CHUNK_SIZE;

	len = 0;
	while (len < bufsz) {
		cnode = get_dentry_chunk(ofile->dentry, chunk_nr);
		if (IS_ERR(cnode))
			return PTR_ERR(cnode);

		cplen = bufsz - len;
		if (cplen > CHUNK_SIZE - chunk_off)
			cplen = CHUNK_SIZE - chunk_off;
		if (read) {
			if (cplen > file_size - len)
				cplen = file_size - len;
			memcpy(buf + len, cnode->chunk_data + chunk_off, cplen);
		} else {
			memcpy(cnode->chunk_data + chunk_off, buf + len, cplen);
			cnode->dirty = 1;
		}
		len += cplen;
		cache_file_chunk(ofile, cnode);

		chunk_nr ++;
		chunk_off = 0;
	}

	if (!read) {
		if ((len + offset) > file_size)
			ofile->dentry->size = len + offset;
		ofile->dentry->mtime = time(NULL);
		ofile->dentry->dirty = 1;
	}

	return len;
}

int read_file(struct open_file *ofile, char *buf, size_t bufsz, off_t offset)
{
	int len;

	lock_file(ofile);
	len = rw_file(ofile, buf, bufsz, offset, 1);
	unlock_file(ofile);

	return len;
}

int write_file(struct open_file *ofile, const char *buf, size_t len, off_t off)
{
	int retv;

	lock_file(ofile);
	retv = rw_file(ofile, (char *)buf, len, off, 0);
	unlock_file(ofile);

	return retv;
}
