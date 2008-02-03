
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "zunkfs.h"

static struct chunk_node *new_chunk_node(unsigned char *chunk_digest,
		unsigned nr_children)
{
	struct chunk_node *cnode;
	int err;

	cnode = malloc(sizeof(struct chunk_node));
	if (!cnode)
		return NULL;

	cnode->child = NULL;
	if (nr_children) {
		cnode->child = calloc(nr_children, sizeof(void *));
		if (!cnode->child) {
			free(cnode);
			errno = ENOMEM;
			return NULL;
		}
	}

	cnode->chunk_digest = chunk_digest;
	cnode->parent = NULL;
	cnode->dirty = 0;
	cnode->ref_count = 0;

	if (!chunk_digest)
		return cnode;

	err = read_chunk(cnode->chunk_data, chunk_digest);
	if (err >= 0)
		return cnode;

	free(cnode);
	errno = -err;
	return NULL;
}

static int grow_chunk_tree(struct chunk_tree *ctree)
{
	struct chunk_node *old_root;
	struct chunk_node *new_root;
	unsigned nr_chunks = ctree->nr_chunks + 1;
	unsigned new_height;

	for (new_height = 0; nr_chunks; new_height ++)
		nr_chunks /= DIGESTS_PER_CHUNK;

	/*
	 * Tree won't grow in height, but still grows 
	 * in # of chunks in it.
	 */
	if (ctree->height == new_height) {
		ctree->nr_chunks ++;
		return 0;
	}

	old_root = ctree->root;

	zero_chunk_digest(old_root->chunk_digest);

	new_root = new_chunk_node(old_root->chunk_digest, DIGESTS_PER_CHUNK);
	if (!new_root)
		return -errno;

	TRACE("new_root=%p old_root=%p\n", new_root, old_root);

	new_root->child[0] = old_root;
	new_root->dirty = 1;
	new_root->ref_count = 2;

	old_root->chunk_digest = new_root->chunk_data;
	old_root->dirty = 1; /* force old_root to update its digest */
	old_root->parent = new_root;

	ctree->root = new_root;
	ctree->nr_chunks ++;
	ctree->height ++;

	put_chunk_node(old_root);

	return 0;
}

static inline unsigned *init_chunk_path(const struct chunk_tree *ctree,
		unsigned chunk_nr, unsigned *path)
{
	if (path) {
		int i;
		for (i = 0; i < ctree->height; i ++) {
			path[i] = chunk_nr % DIGESTS_PER_CHUNK;
			chunk_nr /= DIGESTS_PER_CHUNK;
		}
	}
	return path;
}

#define alloca_chunk_path(ctree) \
	alloca(sizeof(unsigned *) * (ctree)->height)

#define path_to_chunk(ctree, chunk_nr) \
	init_chunk_path(ctree, chunk_nr, alloca_chunk_path(ctree))

struct chunk_node *get_chunk_nr(struct chunk_tree *ctree, unsigned chunk_nr)
{
	struct chunk_node *cnode;
	struct chunk_node *parent;
	unsigned *chunk_path;
	unsigned *tmp_path;
	unsigned char *chunk_digest;
	int i, err;

	TRACE("%p %u max=%u\n", ctree, chunk_nr, ctree->nr_chunks);

	errno = EINVAL;
	if (chunk_nr > ctree->nr_chunks)
		return NULL;

	if (chunk_nr == ctree->nr_chunks) {
		TRACE("growing chunk tree\n");
		/*
		 * grow_chunk_tree will check if tree needs to 
		 * grow in height or not.
		 */
		err = grow_chunk_tree(ctree);
		if (err < 0) {
			errno = -err;
			return NULL;
		}

		assert(chunk_nr != 0);

		/*
		 * This is used to check which internal chunk
		 * nodes need to be initialized. 'tmp_path' 
		 * saves the path needed for the previously
		 * last node.
		 */
		tmp_path = path_to_chunk(ctree, chunk_nr - 1);
		if (!tmp_path)
			return NULL;
	}

	chunk_path = path_to_chunk(ctree, chunk_nr);
	if (!chunk_path)
		return NULL;

	parent = NULL;
	cnode = ctree->root;
	i = ctree->height;

	assert(cnode != NULL);

	while (i--) {
		parent = cnode;
		cnode = cnode->child[chunk_path[i]];
		if (cnode)
			continue;

		TRACE("adding %s chunk (%d)\n", i ? "internal" : "leaf", i);

		/*
		 * When adding a leaf chunk, make sure that all levels
		 * of the chunk tree are initialized.
		 */
		chunk_digest = parent->chunk_data + i * CHUNK_DIGEST_LEN;
		if (tmp_path && chunk_path[i] != tmp_path[i])
			zero_chunk_digest(chunk_digest);

		/*
		 * For leaf chunks, ->child will not be initalized.
		 * But it may be used by others.
		 */
		cnode = new_chunk_node(chunk_digest, i ? DIGESTS_PER_CHUNK : 0);
		if (!cnode)
			return NULL;

		TRACE("new cnode=%p (parent=%p)\n", cnode, parent);

		cnode->parent = parent;

		parent->child[chunk_path[i]] = cnode;
		parent->dirty = 1;
		parent->ref_count ++;
	}

	cnode->ref_count ++;
	return cnode;
}

static int flush_chunk_node(struct chunk_node *cnode)
{
	int err;

	if (cnode->dirty) {
		err = write_chunk(cnode->chunk_data, cnode->chunk_digest);
		if (err < 0)
			return err;
		if (cnode->parent)
			cnode->parent->dirty = 1;
		cnode->dirty = 0;
	}

	return 0;
}

static inline unsigned chunk_nr(const struct chunk_node *cnode)
{
	const struct chunk_node *parent = cnode->parent;
	assert(parent != NULL);
	return (cnode->chunk_digest - parent->chunk_data) / CHUNK_DIGEST_LEN;
}

static void free_chunk_node(struct chunk_node *cnode)
{
	struct chunk_node *parent;
	int saved_errno = errno;
	int err;

	for (;;) {
		err = flush_chunk_node(cnode);
		if (err < 0) {
			WARNING("flush_chunk_node(%p): %s\n", cnode, 
					strerror(-err));
		}

		if (cnode->child)
			free(cnode->child);

		parent = cnode->parent;
		assert(parent != NULL);

		parent->child[chunk_nr(cnode)] = NULL;
		free(cnode);

		TRACE("parent=%p %d\n", parent, parent->ref_count);

		if (--parent->ref_count)
			break;

		cnode = parent;
	}

	errno = saved_errno;
}

void __put_chunk_node(struct chunk_node *cnode, const char *caller)
{
	TRACE("%s: %p %u\n", caller, cnode, cnode->ref_count);
	if (!--cnode->ref_count)
		free_chunk_node(cnode);
}

int init_chunk_tree(struct chunk_tree *ctree, unsigned nr_chunks,
		unsigned char *root_digest)
{
	if (nr_chunks == 0)
		return -EINVAL;
	if (!root_digest)
		return -EINVAL;

	ctree->nr_chunks = nr_chunks;
	for (ctree->height = 0; nr_chunks; ctree->height ++)
		nr_chunks /= DIGESTS_PER_CHUNK;

	ctree->root = new_chunk_node(root_digest,
			ctree->height ? DIGESTS_PER_CHUNK : 0);
	if (!ctree->root)
		return -errno;

	ctree->root->ref_count ++;
	return 0;
}

void free_chunk_tree(struct chunk_tree *ctree)
{
	struct chunk_node *croot = ctree->root;

	assert(croot->ref_count == 1);

	if (croot->child)
		free(croot->child);
	free(croot);
}

static int flush_chunk_node_recursive(struct chunk_node *cnode, unsigned height)
{
	unsigned i;
	int err;

	if (height) {
		for (i = 0; i < DIGESTS_PER_CHUNK; i ++) {
			if (!cnode->child[i])
				continue;
			err = flush_chunk_node_recursive(cnode, height - 1);
			if (err < 0)
				return err;
		}
	}

	return flush_chunk_node(cnode);
}

int flush_chunk_tree(struct chunk_tree *ctree)
{
	return flush_chunk_node_recursive(ctree->root, ctree->height);
}

