
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "zunkfs.h"

static struct chunk_node *new_chunk_node(struct chunk_tree *ctree,
		unsigned char *chunk_digest, int leaf)
{
	struct chunk_node *cnode;
	int err;

	assert(chunk_digest != NULL);

	cnode = malloc(sizeof(struct chunk_node));
	if (!cnode)
		return ERR_PTR(ENOMEM);

	cnode->child = NULL;
	cnode->chunk_digest = chunk_digest;
	cnode->parent = NULL;
	cnode->dirty = 0;
	cnode->ref_count = 0;

	err = read_chunk(cnode->chunk_data, chunk_digest);
	if (err < 0)
		goto error;

	if (!leaf) {
		err = -ENOMEM;
		cnode->child = calloc(DIGESTS_PER_CHUNK, sizeof(void *));
		if (!cnode->child)
			goto error;
	}

	return cnode;
error:
	free(cnode);
	return ERR_PTR(-err);
}

static int grow_chunk_tree(struct chunk_tree *ctree)
{
	struct chunk_node *new_root;
	struct chunk_node *old_root;

	old_root = ctree->root;

	new_root = new_chunk_node(ctree, old_root->chunk_digest, 0);
	if (IS_ERR(new_root))
		return -PTR_ERR(new_root);


	memset(new_root->chunk_data, 0, CHUNK_SIZE);

	old_root->parent = new_root;
	old_root->chunk_digest = new_root->chunk_data;
	memcpy(old_root->chunk_digest, new_root->chunk_digest, CHUNK_DIGEST_LEN);

	new_root->dirty = 1;
	new_root->ref_count = 2; /* old_root & ctree */
	new_root->child[0] = old_root;

	ctree->height ++;
	ctree->root = new_root;

	put_chunk_node(old_root);

	return 0;
}

struct chunk_node *get_nth_chunk(struct chunk_tree *ctree, unsigned chunk_nr)
{
	struct chunk_node *parent;
	struct chunk_node *cnode;
	unsigned *path = NULL;
	unsigned *max_path = NULL;
	unsigned nr;
	unsigned char *digest;
	int i, err;

	if (chunk_nr > ctree->nr_leafs)
		return ERR_PTR(EINVAL);

again:
	path = alloca(sizeof(unsigned *) * ctree->height);
	assert(path != NULL);

	nr = chunk_nr;
	for (i = 0; i < ctree->height; i ++) {
		path[i] = nr % DIGESTS_PER_CHUNK;
		nr /= DIGESTS_PER_CHUNK;
	}

	if (nr) {
		err = grow_chunk_tree(ctree);
		if (err)
			return ERR_PTR(-err);
		goto again;
	}

	if (chunk_nr == ctree->nr_leafs) {
		max_path = alloca(sizeof(unsigned *) * ctree->height);
		nr = ctree->nr_leafs - 1;
		for (i = 0; i < ctree->height; i ++) {
			max_path[i] = nr % DIGESTS_PER_CHUNK;
			nr /= DIGESTS_PER_CHUNK;
		}
		ctree->nr_leafs ++;
	}

	cnode = ctree->root;
	i = ctree->height;
	while (i --) {
		parent = cnode;
		assert(parent->child != NULL);

		cnode = parent->child[path[i]];
		if (cnode)
			continue;

		digest = parent->chunk_data + path[i] * CHUNK_DIGEST_LEN;
		if (max_path && max_path[i] != path[i]) {
			zero_chunk_digest(digest);
			parent->dirty = 1;
		}

		cnode = new_chunk_node(ctree, digest, !i);
		if (IS_ERR(cnode))
			return cnode;

		cnode->parent = parent;
		parent->child[path[i]] = cnode;
		parent->ref_count ++;
	}

	cnode->ref_count ++;
	return cnode;
}

static inline unsigned chunk_nr(const struct chunk_node *cnode)
{
	const struct chunk_node *parent = cnode->parent;
	assert(parent != NULL);
	return (cnode->chunk_digest - parent->chunk_data) / CHUNK_DIGEST_LEN;
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

		if (--parent->ref_count)
			break;

		cnode = parent;
	}

	errno = saved_errno;
}

void __put_chunk_node(struct chunk_node *cnode, const char *caller)
{
	if (!--cnode->ref_count)
		free_chunk_node(cnode);
}

int init_chunk_tree(struct chunk_tree *ctree, unsigned nr_leafs,
		unsigned char *root_digest)
{
	if (!root_digest)
		return -EINVAL;

	ctree->nr_leafs = nr_leafs;
	ctree->height = 0;
	while (nr_leafs >= DIGESTS_PER_CHUNK) {
		ctree->height ++;
		nr_leafs /= DIGESTS_PER_CHUNK;
	}

	ctree->root = new_chunk_node(ctree, root_digest, !ctree->height);
	if (IS_ERR(ctree->root))
		return -PTR_ERR(ctree->root);

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

