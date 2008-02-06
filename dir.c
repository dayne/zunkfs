
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/stat.h>

#include "zunkfs.h"

static struct dentry *root_dentry = NULL;

static inline unsigned dentry_index(const struct dentry *dentry)
{
	return dentry->ddent -
		(struct disk_dentry *)dentry->ddent_cnode->chunk_data;
}

static struct dentry *new_dentry(struct dentry *parent,
		struct disk_dentry *ddent, struct chunk_node *ddent_cnode)
{
	struct dentry *dentry;
	unsigned nr_chunks;
	int err;
	
	dentry = malloc(sizeof(struct dentry));
	if (!dentry)
		return ERR_PTR(ENOMEM);

	dentry->ddent = ddent;
	dentry->ddent_cnode = ddent_cnode;
	dentry->parent = parent;
	dentry->ref_count = 0;

	if (S_ISDIR(ddent->mode))
		nr_chunks = (ddent->size + DIRENTS_PER_CHUNK - 1) / 
			DIRENTS_PER_CHUNK;
	else
		nr_chunks = (ddent->size + CHUNK_SIZE - 1) / CHUNK_SIZE;

	err = init_chunk_tree(&dentry->chunk_tree, nr_chunks, ddent->digest);
	if (err < 0)  {
		free(dentry);
		return ERR_PTR(-err);
	}

	if (parent) {
		parent->ref_count ++;
		assert(ddent_cnode != NULL);
		assert(!IS_ERR(ddent_cnode));
		ddent_cnode->child[dentry_index(dentry)] = dentry;
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

	chunk_nr = nr / DIRENTS_PER_CHUNK;
	chunk_off = nr % DIRENTS_PER_CHUNK;

	cnode = get_nth_chunk(&parent->chunk_tree, chunk_nr);
	if (IS_ERR(cnode))
		return (void *)cnode;

	if (!cnode->child) {
		cnode->child = calloc(DIRENTS_PER_CHUNK,
				sizeof(struct dentry *));
		if (!cnode->child)
			return ERR_PTR(ENOMEM);
	}

	dentry = cnode->child[chunk_off];
	if (dentry)
		goto got_dentry;

	ddent = (struct disk_dentry *)cnode->chunk_data + chunk_off;
	if (nr == parent->ddent->size)
		zero_chunk_digest(ddent->digest);

	dentry = new_dentry(parent, ddent, cnode);
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
	if (!S_ISDIR(parent->ddent->mode))
		return ERR_PTR(ENOTDIR);
	if (nr >= parent->ddent->size)
		return ERR_PTR(ENOENT);
	return __get_nth_dentry(parent, nr);
}

static void free_dentry(struct dentry *dentry)
{
	struct dentry *parent;

	for (;;) {
		parent = dentry->parent;

		assert(parent != NULL);
		assert(dentry->ddent != NULL);
		assert(dentry->ddent_cnode != NULL);

		free_chunk_tree(&dentry->chunk_tree);

		dentry->ddent_cnode->child[dentry_index(dentry)] = NULL;
		put_chunk_node(dentry->ddent_cnode);

		free(dentry);

		if (--parent->ref_count)
			break;
		dentry = parent;
	}
}

void put_dentry(struct dentry *dentry)
{
	if (!--dentry->ref_count)
		free_dentry(dentry);
}

struct dentry *add_dentry(struct dentry *parent, const char *name, mode_t mode)
{
	struct dentry *dentry;

	if (strlen(name) >= DDENT_NAME_MAX)
		return ERR_PTR(ENAMETOOLONG);

	dentry = __get_nth_dentry(parent, parent->ddent->size);
	if (IS_ERR(dentry))
		return dentry;

	strcpy(dentry->ddent->name, name);

	dentry->ddent->mode = mode;
	dentry->ddent->size = 0;
	dentry->ddent->ctime = time(NULL);
	dentry->ddent->mtime = dentry->ddent->ctime;

	dentry->ddent_cnode->dirty = 1;

	parent->ddent->size ++;
	parent->ddent->mtime = time(NULL);

	if (parent->ddent_cnode)
		parent->ddent_cnode->dirty = 1;

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

	a->ddent_cnode->child[dentry_index(a)] = a;
	b->ddent_cnode->child[dentry_index(b)] = b;

	tmp_ddent = *a->ddent;
	*a->ddent = *b->ddent;
	*b->ddent = tmp_ddent;

	a->ddent_cnode->dirty = 1;
	b->ddent_cnode->dirty = 1;
}

int del_dentry(struct dentry *dentry)
{
	struct dentry *parent;
	struct dentry *tmp;

	if (dentry->ref_count > 1)
		return -EBUSY;

	parent = dentry->parent;
	assert(parent->ddent->size >= 1);

	if (parent->ddent->size > 1) {
		tmp = __get_nth_dentry(parent, parent->ddent->size - 1);
		if (IS_ERR(tmp))
			return -PTR_ERR(tmp);
		if (tmp != dentry)
			swap_dentries(dentry, tmp);
		put_dentry(tmp);
	}

	dentry->ddent_cnode->child[dentry_index(dentry)] = NULL;

	parent->ddent->size --;
	parent->ddent->mtime = time(NULL);

	if (parent->ddent_cnode)
		parent->ddent_cnode->dirty = 1;

	return 0;
}

static struct dentry *lookup1(struct dentry *parent, const char *name, int len)
{
	struct dentry *dentry;
	unsigned nr;

	assert(S_ISDIR(parent->ddent->mode));

	if (!strncmp(name, ".", len)) {
		parent->ref_count ++;
		return parent;
	}

	if (!strncmp(name, "..", len)) {
		dentry = parent->parent ?: parent;
		dentry->ref_count ++;
		return dentry;
	}

	for (nr = 0; nr < parent->ddent->size; nr ++) {
		dentry = __get_nth_dentry(parent, nr);
		if (IS_ERR(dentry))
			return dentry;
		if (strncmp(dentry->ddent->name, name, len))
			continue;
		if (!dentry->ddent->name[len]) {
			dentry->ref_count ++;
			return dentry;
		}
	}

	return NULL;
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
	dentry->ref_count ++;

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

int set_root(struct disk_dentry *ddent)
{
	if (!S_ISDIR(ddent->mode))
		return -ENOTDIR;

	assert(root_dentry == NULL || IS_ERR(root_dentry));

	root_dentry = new_dentry(NULL, ddent, NULL);
	if (IS_ERR(root_dentry))
		return -PTR_ERR(root_dentry);

	root_dentry->ref_count ++;
	return 0;
}

static void __attribute__((constructor)) dir_ctor(void)
{
	assert(DIRENTS_PER_CHUNK != 0);
}

