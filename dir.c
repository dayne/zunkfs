
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

static struct dentry *root_dentry = NULL;

#define children_of(cnode) \
	((struct dentry **)(cnode)->_private)
#define dentry_ptr(dentry) \
	children_of((dentry)->ddent_cnode)[dentry_index(dentry)]

static inline unsigned dentry_index(const struct dentry *dentry)
{
	return dentry->ddent -
		(struct disk_dentry *)dentry->ddent_cnode->chunk_data;
}

static struct chunk_tree_operations dentry_ctree_ops = {
	.free_private = free,
	.read_chunk   = read_chunk,
	.write_chunk  = write_chunk
};

static struct dentry *new_dentry(struct dentry *parent,
		struct disk_dentry *ddent, struct chunk_node *ddent_cnode,
		struct mutex *ddent_mutex)
{
	struct dentry *dentry;
	unsigned nr_chunks;
	int err;

	assert(have_mutex(ddent_mutex));
	
	dentry = malloc(sizeof(struct dentry));
	if (!dentry)
		return ERR_PTR(ENOMEM);

	dentry->ddent = ddent;
	dentry->ddent_cnode = ddent_cnode;
	dentry->ddent_mutex = ddent_mutex;
	dentry->parent = parent;
	dentry->ref_count = 0;

	init_mutex(&dentry->mutex);

	if (S_ISDIR(ddent->mode))
		nr_chunks = (ddent->size + DIRENTS_PER_CHUNK - 1) / 
			DIRENTS_PER_CHUNK;
	else
		nr_chunks = (ddent->size + CHUNK_SIZE - 1) / CHUNK_SIZE;

	err = init_chunk_tree(&dentry->chunk_tree, nr_chunks, ddent->digest,
			&dentry_ctree_ops);
	if (err < 0)  {
		free(dentry);
		return ERR_PTR(-err);
	}

	if (parent) {
		locked_inc(&parent->ref_count, parent->ddent_mutex);
		assert(ddent_cnode != NULL);
		assert(!IS_ERR(ddent_cnode));
		dentry_ptr(dentry) = dentry;
	}

	return dentry;
}

static struct dentry *__get_nth_dentry(struct dentry *parent, unsigned nr)
{
	struct dentry *dentry;
	struct disk_dentry *ddent;
	struct chunk_node *cnode;
	unsigned chunk_nr;
	unsigned chunk_off;

	assert(have_mutex(&parent->mutex));

	chunk_nr = nr / DIRENTS_PER_CHUNK;
	chunk_off = nr % DIRENTS_PER_CHUNK;

	cnode = get_nth_chunk(&parent->chunk_tree, chunk_nr);
	if (IS_ERR(cnode))
		return (void *)cnode;

	if (!cnode->_private) {
		cnode->_private = calloc(DIRENTS_PER_CHUNK,
				sizeof(struct dentry *));
		if (!cnode->_private)
			return ERR_PTR(ENOMEM);
	}

	dentry = children_of(cnode)[chunk_off];
	if (dentry)
		goto got_dentry;

	ddent = (struct disk_dentry *)cnode->chunk_data + chunk_off;
	if (nr == parent->ddent->size)
		zero_chunk_digest(ddent->digest);

	dentry = new_dentry(parent, ddent, cnode, &parent->mutex);
	if (IS_ERR(dentry))
		goto error;

got_dentry:
	if (dentry->ref_count)
		put_chunk_node(cnode);
	dentry->ref_count ++;
	return dentry;
error:
	put_chunk_node(cnode);
	return dentry;
}

struct dentry *get_nth_dentry(struct dentry *parent, unsigned nr)
{
	struct dentry *dentry;

	if (!S_ISDIR(parent->ddent->mode))
		return ERR_PTR(ENOTDIR);
	if (nr >= parent->ddent->size)
		return ERR_PTR(ENOENT);

	lock(&parent->mutex);
	dentry = __get_nth_dentry(parent, nr);
	unlock(&parent->mutex);

	return dentry;
}

static void free_dentry(struct dentry *dentry)
{
	assert(have_mutex(dentry->ddent_mutex));
	assert(dentry->ref_count == 0);
	assert(dentry->ddent != NULL);
	assert(dentry->ddent_cnode != NULL);

	free_chunk_tree(&dentry->chunk_tree);

	dentry_ptr(dentry) = NULL;
	put_chunk_node(dentry->ddent_cnode);

	free(dentry);
}

/*
 * Call this only if you hold the parent's mutex _and_ ref count.
 */
static void __put_dentry(struct dentry *dentry)
{
	struct dentry *parent;

	assert(have_mutex(dentry->ddent_mutex));

	if (!--dentry->ref_count) {
		parent = dentry->parent;
		free_dentry(dentry);
		locked_dec(&parent->ref_count, parent->ddent_mutex);
		assert(parent->ref_count != 0);
	}
}

void put_dentry(struct dentry *dentry)
{
	struct dentry *parent;

	for (;;) {
		lock(dentry->ddent_mutex);
		if (--dentry->ref_count) {
			unlock(dentry->ddent_mutex);
			return;
		}

		parent = dentry->parent;
		assert(parent != NULL);
		assert(&parent->mutex == dentry->ddent_mutex);

		free_dentry(dentry);
		unlock(&parent->mutex);
		dentry = parent;
	}
}

struct dentry *add_dentry(struct dentry *parent, const char *name, mode_t mode)
{
	struct dentry *dentry;

	if (strlen(name) >= DDENT_NAME_MAX)
		return ERR_PTR(ENAMETOOLONG);

	lock(&parent->mutex);

	dentry = __get_nth_dentry(parent, parent->ddent->size);
	if (IS_ERR(dentry))
		goto out;

	namcpy(dentry->ddent->name, name);

	dentry->ddent->mode = mode;
	dentry->ddent->size = 0;
	dentry->ddent->ctime = time(NULL);
	dentry->ddent->mtime = dentry->ddent->ctime;

	dentry->ddent_cnode->dirty = 1;

	lock(parent->ddent_mutex);
	parent->ddent->size ++;
	parent->ddent->mtime = time(NULL);
	unlock(parent->ddent_mutex);

	if (parent->ddent_cnode)
		parent->ddent_cnode->dirty = 1;

out:
	unlock(&parent->mutex);
	return dentry;
}

static void swap_dentries(struct dentry *a, struct dentry *b)
{
	struct disk_dentry *ddent;
	struct disk_dentry tmp_ddent;
	struct chunk_node *cnode;

	ddent = a->ddent;
	cnode = a->ddent_cnode;

	a->ddent = b->ddent;
	a->ddent_cnode = b->ddent_cnode;

	b->ddent = ddent;
	b->ddent_cnode = cnode;

	dentry_ptr(a) = a;
	dentry_ptr(b) = b;

	tmp_ddent = *a->ddent;
	*a->ddent = *b->ddent;
	*b->ddent = tmp_ddent;

	a->ddent_cnode->dirty = 1;
	b->ddent_cnode->dirty = 1;
}

int del_dentry(struct dentry *dentry)
{
	struct dentry *parent;
	struct dentry *tmp = NULL;
	int err;

	lock(dentry->ddent_mutex);

	err = -EBUSY;
	if (dentry->ref_count > 1)
		goto out;

	parent = dentry->parent;
	assert(parent->ddent->size >= 1);

	if (parent->ddent->size > 1) {
		tmp = __get_nth_dentry(parent, parent->ddent->size - 1);
		err = -PTR_ERR(tmp);
		if (IS_ERR(tmp))
			goto out;
		if (tmp != dentry)
			swap_dentries(dentry, tmp);
		__put_dentry(tmp);
	}

	dentry_ptr(dentry) = NULL;

	lock(parent->ddent_mutex);
	parent->ddent->size --;
	parent->ddent->mtime = time(NULL);

	if (parent->ddent_cnode)
		parent->ddent_cnode->dirty = 1;
	unlock(parent->ddent_mutex);

	err = 0;
out:
	unlock(&parent->mutex);
	return err;
}

static struct dentry *lookup1(struct dentry *parent, const char *name, int len)
{
	struct dentry *dentry;
	unsigned nr;

	assert(S_ISDIR(parent->ddent->mode));

	if (!strncmp(name, ".", len)) {
		locked_inc(&parent->ref_count, parent->ddent_mutex);
		return parent;
	}

	if (!strncmp(name, "..", len)) {
		dentry = parent->parent ?: parent;
		locked_inc(&dentry->ref_count, dentry->ddent_mutex);
		return dentry;
	}

	lock(&parent->mutex);
	for (nr = 0; nr < parent->ddent->size; nr ++) {
		dentry = __get_nth_dentry(parent, nr);
		if (IS_ERR(dentry))
			goto out;
		if (namcmp(dentry->ddent->name, name, len))
			continue;
		if (!dentry->ddent->name[len]) {
			dentry->ref_count ++;
			goto out;
		}
	}

	dentry = NULL;
out:
	unlock(&parent->mutex);
	return dentry;
}

struct dentry *find_dentry_parent(const char *path, struct dentry **pparent,
		const char **name)
{
	struct dentry *parent;
	struct dentry *dentry;
	char *next;
	int len;

	assert(root_dentry != NULL && !IS_ERR(root_dentry));

	parent = NULL;
	dentry = root_dentry;
	locked_inc(&dentry->ref_count, dentry->ddent_mutex);

	for (;;) {
		parent = dentry;
		next = strchr(path, '/');
		len = next ? next - path : strlen(path);
		dentry = lookup1(parent, path, len);
		if (IS_ERR(dentry)) {
			put_dentry(parent);
			return dentry;
		}
		if (!next) {
			if (pparent)
				*pparent = parent;
			else
				put_dentry(parent);
			if (name)
				*name = path;
			return dentry;
		}
		put_dentry(parent);
		if (!dentry)
			return ERR_PTR(ENOENT);
		path = next + 1;
	}
}

int set_root(struct disk_dentry *ddent, struct mutex *ddent_mutex)
{
	int err;

	if (!S_ISDIR(ddent->mode))
		return -ENOTDIR;

	assert(root_dentry == NULL || IS_ERR(root_dentry));

	lock(ddent_mutex);
	root_dentry = new_dentry(NULL, ddent, NULL, ddent_mutex);
	err = -PTR_ERR(root_dentry);
	if (IS_ERR(root_dentry))
		goto out;

	root_dentry->ref_count ++;
	err = 0;
out:
	unlock(ddent_mutex);
	return 0;
}

static void __attribute__((constructor)) dir_ctor(void)
{
	assert(DIRENTS_PER_CHUNK != 0);
}

