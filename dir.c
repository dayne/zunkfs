
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

static int read_dentry_chunk(unsigned char *chunk, const unsigned char *digest)
{
	const struct chunk_node *cnode;
	const struct dentry *dentry;
	int i, err;

	cnode = container_of(chunk, struct chunk_node, chunk_data);
	dentry = container_of(cnode->ctree, struct dentry, chunk_tree);

	assert(dentry->secret_chunk != NULL);

	/*
	 * Chunk will be empty, so nothing to read.
	 */
	if (!dentry->size)
		return 0;

	err = read_chunk(chunk, digest);
	if (err < 0)
		return err;

	for (i = 0; i < CHUNK_SIZE; i ++)
		chunk[i] ^= dentry->secret_chunk[i];

	return err;
}

static int write_dentry_chunk(const unsigned char *chunk, unsigned char *digest)
{
	const struct chunk_node *cnode;
	const struct dentry *dentry;
	unsigned char real_chunk[CHUNK_SIZE];
	int i, err;

	cnode = container_of(chunk, struct chunk_node, chunk_data);
	dentry = container_of(cnode->ctree, struct dentry, chunk_tree);

	assert(dentry->secret_chunk != NULL);

	for (i = 0; i < CHUNK_SIZE; i ++)
		real_chunk[i] = chunk[i] ^ dentry->secret_chunk[i];

	err = write_chunk(real_chunk, digest);
	if (err < 0)
		return err;

	return err;
}

static struct chunk_tree_operations dentry_ctree_ops = {
	.free_private = free,
	.read_chunk   = read_dentry_chunk,
	.write_chunk  = write_dentry_chunk,
};

static struct dentry *new_dentry(struct dentry *parent,
		struct disk_dentry *ddent, struct chunk_node *ddent_cnode,
		struct mutex *ddent_mutex)
{
	struct dentry *dentry;

	assert(have_mutex(ddent_mutex));
	
	dentry = malloc(sizeof(struct dentry));
	if (!dentry)
		return ERR_PTR(ENOMEM);

	dentry->ddent = ddent;
	dentry->ddent_cnode = ddent_cnode;
	dentry->ddent_mutex = ddent_mutex;
	dentry->parent = parent;
	dentry->size = ddent->size;
	dentry->mtime = ddent->mtime;

	init_mutex(&dentry->mutex);
	dentry->ref_count = 0;
	memset(&dentry->chunk_tree, 0, sizeof(struct chunk_tree));
	dentry->secret_chunk = NULL;

	if (parent) {
		locked_inc(&parent->ref_count, parent->ddent_mutex);
		assert(ddent_cnode != NULL);
		assert(!IS_ERR(ddent_cnode));
		dentry_ptr(dentry) = dentry;
	}

	return dentry;
}

int init_disk_dentry(struct disk_dentry *ddent)
{
	/*
	 * To properly zero out a dentry chunk, the digest must match 
	 * the secret digest.
	 */
	int err = random_chunk_digest(ddent->secret_digest);
	if (err < 0)
		return err;

	memcpy(ddent->digest, ddent->secret_digest, CHUNK_DIGEST_LEN);
	return err;
}

static inline unsigned ddent_chunk_count(struct disk_dentry *ddent)
{
	if (S_ISREG(ddent->mode))
		return (ddent->size + CHUNK_SIZE - 1) / CHUNK_SIZE;
	assert(S_ISDIR(ddent->mode));
	return (ddent->size + DIRENTS_PER_CHUNK - 1) / DIRENTS_PER_CHUNK;
}

struct chunk_node *get_dentry_chunk(struct dentry *dentry, unsigned chunk_nr)
{
	assert(have_mutex(&dentry->mutex));

	if (dentry->chunk_tree.root == NULL) {
		int err;

		/*
		 * secret must be read before the root chunk is read.
		 */
		dentry->secret_chunk = malloc(CHUNK_SIZE);
		if (!dentry->secret_chunk)
			return ERR_PTR(ENOMEM);
		err = read_chunk(dentry->secret_chunk,
				dentry->ddent->secret_digest);
		if (err < 0)
			return ERR_PTR(-err);
		err = init_chunk_tree(&dentry->chunk_tree,
				ddent_chunk_count(dentry->ddent),
				dentry->ddent->digest, &dentry_ctree_ops);
		if (err < 0)
			return ERR_PTR(-err);
	}

	return get_nth_chunk(&dentry->chunk_tree, chunk_nr);
}

static struct dentry *__get_nth_dentry(struct dentry *parent, unsigned nr)
{
	struct dentry *dentry;
	struct disk_dentry *ddent;
	struct chunk_node *cnode;
	unsigned chunk_nr;
	unsigned chunk_off;
	int err;

	assert(have_mutex(&parent->mutex));

	chunk_nr = nr / DIRENTS_PER_CHUNK;
	chunk_off = nr % DIRENTS_PER_CHUNK;

	cnode = get_dentry_chunk(parent, chunk_nr);
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
	if (nr == parent->size) {
		err = init_disk_dentry(ddent);
		if (err < 0) {
			dentry = ERR_PTR(-err);
			goto error;
		}
	}

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
	if (nr >= parent->size)
		return ERR_PTR(ENOENT);

	lock(&parent->mutex);
	dentry = __get_nth_dentry(parent, nr);
	unlock(&parent->mutex);

	return dentry;
}

/*
 * Dentry must be either about-to-be freed or have
 * it's mutex locked.
 */
static void flush_dentry(struct dentry *dentry)
{
	assert(have_mutex(dentry->ddent_mutex));
	assert(have_mutex(&dentry->mutex) || dentry->ref_count == 0);

	if (dentry->chunk_tree.root) {
		int err = flush_chunk_tree(&dentry->chunk_tree);
		if (err < 0) {
			WARNING("flush_dentry %p: %s\n", dentry,
					strerror(-err));
			return;
		}
		if (dentry->chunk_tree.root->dirty)
			dentry->dirty = 1;
	}
	
	if (dentry->dirty) {
		dentry->ddent->size = dentry->size;
		dentry->ddent->mtime = dentry->mtime;
		if (dentry->ddent_cnode)
			dentry->ddent_cnode->dirty = 1;
		dentry->dirty = 0;
	}
}

static void free_dentry(struct dentry *dentry)
{
	assert(have_mutex(dentry->ddent_mutex));
	assert(dentry->ref_count == 0);
	assert(dentry->ddent != NULL);
	assert(dentry->ddent_cnode != NULL);

	flush_dentry(dentry);

	if (dentry->chunk_tree.root) {
		assert(dentry->secret_chunk != NULL);
		free(dentry->secret_chunk);
		free_chunk_tree(&dentry->chunk_tree);
	}

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
	time_t now;

	if (strlen(name) >= DDENT_NAME_MAX)
		return ERR_PTR(ENAMETOOLONG);

	lock(&parent->mutex);

	dentry = __get_nth_dentry(parent, parent->size);
	if (IS_ERR(dentry))
		goto out;

	now = time(NULL);

	namcpy(dentry->ddent->name, name);

	dentry->ddent->mode = mode;
	dentry->ddent->size = 0;
	dentry->ddent->ctime = now;
	dentry->ddent->mtime = now;

	dentry->dirty = 1;
	dentry->size = 0;
	dentry->mtime = now;

	parent->dirty = 1;
	parent->size ++;
	parent->mtime = now;
out:
	unlock(&parent->mutex);
	return dentry;
}

static void swap_dentries(struct dentry *a, struct dentry *b)
{
	struct disk_dentry *ddent;
	struct disk_dentry tmp_ddent;
	struct chunk_node *cnode;
	struct mutex *ddent_mutex;
	struct dentry *parent;

	assert(have_mutex(a->ddent_mutex));
	assert(have_mutex(b->ddent_mutex));

	ddent = a->ddent;
	cnode = a->ddent_cnode;
	parent = a->parent;
	ddent_mutex = a->ddent_mutex;

	a->ddent = b->ddent;
	a->ddent_cnode = b->ddent_cnode;
	a->parent = b->parent;
	a->ddent_mutex = b->ddent_mutex;

	b->ddent = ddent;
	b->ddent_cnode = cnode;
	b->parent = parent;
	b->ddent_mutex = ddent_mutex;

	dentry_ptr(a) = a;
	dentry_ptr(b) = b;

	tmp_ddent = *a->ddent;
	*a->ddent = *b->ddent;
	*b->ddent = tmp_ddent;

	a->ddent_cnode->dirty = 1;
	b->ddent_cnode->dirty = 1;
}

static int make_last_dentry(struct dentry *dentry, struct dentry *parent)
{
	assert(have_mutex(&parent->mutex));

	if (parent->size > 1) {
		struct dentry *tmp = __get_nth_dentry(parent, parent->size - 1);
		if (IS_ERR(tmp))
			return -PTR_ERR(tmp);
		if (tmp != dentry)
			swap_dentries(dentry, tmp);
		__put_dentry(tmp);
	}

	return 0;
}

static void __del_dentry(struct dentry *dentry, struct dentry *parent)
{
	assert(have_mutex(&parent->mutex));

	dentry_ptr(dentry) = NULL;

	parent->size --;
	parent->dirty = 1;
	parent->mtime = time(NULL);
}

int del_dentry(struct dentry *dentry)
{
	struct dentry *parent = NULL;
	int err;

	lock(dentry->ddent_mutex);
	parent = dentry->parent;
	assert(parent->size >= 1);

	err = -EBUSY;
	if (dentry->ref_count > 1)
		goto out;

	err = make_last_dentry(dentry, parent);
	if (err)
		goto out;

	__del_dentry(dentry, parent);
out:
	unlock(&parent->mutex);
	return err;
}

static struct dentry *lookup(struct dentry *parent, const char *name, int len)
{
	struct dentry *prev = NULL;
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
	for (nr = 0; nr < parent->size; nr ++) {
		dentry = __get_nth_dentry(parent, nr);
		if (IS_ERR(dentry))
			goto out;
		if (!namcmp(dentry->ddent->name, name, len) &&
				!dentry->ddent->name[len])
			goto out;
		if (prev)
			__put_dentry(prev);
		prev = dentry;
	}

	dentry = NULL;
out:
	if (prev)
		__put_dentry(prev);
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
		dentry = lookup(parent, path, len);
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
	if (IS_ERR(root_dentry)) {
		err = -PTR_ERR(root_dentry);
		goto out;
	}

	root_dentry->ref_count ++;
	err = 0;
out:
	unlock(ddent_mutex);
	return 0;
}

void flush_root(void)
{
	assert(root_dentry != NULL);

	lock(&root_dentry->mutex);
	lock(root_dentry->ddent_mutex);
	flush_dentry(root_dentry);
	unlock(root_dentry->ddent_mutex);
	unlock(&root_dentry->mutex);
}

struct dentry *create_dentry(const char *path, mode_t mode)
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

static struct dentry *lock_order(struct dentry *a, struct dentry *b)
{
	struct dentry *c;

	for (c = a; c; c = c->parent)
		if (c->parent == b)
			return a;

	for (c = b; b; b = b->parent)
		if (b->parent == a)
			return b;

	return (b > a) ? a : b;
}

static int __rename_dentry(struct dentry *dentry, const char *new_name,
		struct dentry *new_parent)
{
	struct dentry *old_parent = dentry->parent;
	struct dentry *shadow;
	struct dentry *tmp;
	int err;

	if (strlen(new_name) >= DDENT_NAME_MAX)
		return -ENAMETOOLONG;
	if (!dentry->parent)
		return -EINVAL;

	/*
	 * Simple case: same directory.
	 */
	if (old_parent == new_parent) {
		lock(dentry->ddent_mutex);
		namcpy(dentry->ddent->name, new_name);
		unlock(dentry->ddent_mutex);
		return 0;
	}

	/*
	 * Can't make a dentry be its own decendent.
	 */
	for (tmp = new_parent; tmp; tmp = tmp->parent)
		if (tmp == dentry)
			return -EINVAL;

	/*
	 * The hard part: moving from one directory to another.
	 * Need to do two things: make it easy to delete dentry 
	 * from old_parent, and allocate a new disk_dentry
	 * in new_parent. The order of these two operations does
	 * not matter, except that locking needs to be consitant
	 * and non-recursive.
	 *
	 * If either one of these operations fails,
	 * the FS is still consistant, and we can bail
	 * out. But after that, it's do or die.
	 */
	tmp = lock_order(old_parent, new_parent);
	if (tmp == new_parent) {
		lock(&new_parent->mutex);
		shadow = __get_nth_dentry(new_parent, new_parent->size);
		if (IS_ERR(shadow)) {
			unlock(&new_parent->mutex);
			return -PTR_ERR(shadow);
		}

		lock(&old_parent->mutex);
		err = make_last_dentry(dentry, old_parent);
		if (err) {
			unlock(&old_parent->mutex);
			unlock(&new_parent->mutex);
			return err;
		}

		swap_dentries(shadow, dentry);
		namcpy(dentry->ddent->name, new_name);

		__del_dentry(shadow, old_parent);
		unlock(&old_parent->mutex);

		new_parent->size ++;
		unlock(&new_parent->mutex);

		put_dentry(shadow);
		return 0;

	} else {
		lock(&old_parent->mutex);
		err = make_last_dentry(dentry, old_parent);
		if (err) {
			unlock(&old_parent->mutex);
			return err;
		}

		lock(&new_parent->mutex);
		shadow = __get_nth_dentry(new_parent, new_parent->size);
		if (IS_ERR(shadow)) {
			unlock(&old_parent->mutex);
			unlock(&new_parent->mutex);
			return -PTR_ERR(shadow);
		}

		swap_dentries(shadow, dentry);
		namcpy(dentry->ddent->name, new_name);

		new_parent->size ++;
		unlock(&new_parent->mutex);

		__del_dentry(shadow, old_parent);
		unlock(&old_parent->mutex);

		put_dentry(shadow);
		return 0;
	}
}

int rename_dentry(struct dentry *dentry, const char *new_name,
		struct dentry *new_parent)
{
	int err;

	/*
	 * Serialize multiple renames of the same dentry.
	 *
	 * XXX: What if the dentry is deleted?
	 *      That should be okay, as a racing lookup & delete
	 *      will result in the delete failing with 
	 *      EBUSY.    
	 */
	lock(&dentry->mutex);
	err = __rename_dentry(dentry, new_name, new_parent);
	unlock(&dentry->mutex);

	return err;
}

