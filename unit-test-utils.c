
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>

#include "zunkfs.h"
#include "zunkfs-tests.h"

#define cnode_array(cnode) \
	((struct chunk_node **)(cnode)->_private)
#define dentry_array(cnode) \
	((struct dentry **)(cnode)->_private)

void dump_cnode(struct chunk_node *cnode, const char *indent, int height,
		void (*dump_leaf)(void **, const char *))
{
	int i;

	if (!cnode)
		return;

	printf("%s%p:%p: %s", indent, cnode, cnode->chunk_digest,
			digest_string(cnode->chunk_digest));
	if (cnode->dirty)
		printf(" [dirty]");
	else if (!verify_chunk(cnode->chunk_data, cnode->chunk_digest))
		printf(" [ERR]");
	printf(" [%s] refcount=%d %p\n", height ? "internal" : "leaf",
			cnode->ref_count, cnode->_private);

	if (!height) {
		if (dump_leaf && cnode->_private)
			dump_leaf(cnode->_private, indent);
	} else {
		for (i = 0; i < DIGESTS_PER_CHUNK; i ++) {
			dump_cnode(cnode_array(cnode)[i], indent - 1,
					height - 1, dump_leaf);
		}
	}
}

void dump_ctree(struct chunk_tree *ctree, const char *indent,
		void (*dump_leaf)(void **child, const char *indent))
{
	printf("%sCTREE %p nr_leafs=%d height=%d\n", indent, ctree,
			ctree->nr_leafs, ctree->height);
	if (ctree->root)
		dump_cnode(ctree->root, indent - 1, ctree->height, dump_leaf);
}

void dump_dentries(void **list, const char *indent)
{
	int i;
	for (i = 0; i < DIRENTS_PER_CHUNK; i ++)
		dump_dentry(list[i], indent);
}

void dump_dentry(struct dentry *dentry, const char *indent)
{
	if (!dentry)
		return;

	printf("%s%p:%p:%p:%p %s ref_count=%d\n", indent, dentry, dentry->ddent,
			dentry->ddent_cnode, dentry->parent,
			dentry->ddent->name, dentry->ref_count);
	dump_ctree(&dentry->chunk_tree, indent, dump_dentries);
}

void dump_dentry_2(struct dentry *dentry, const char *indent)
{
	struct dentry *child;
	int i;

	if (!dentry)
		return;

	printf("%s%p:%p:%p:%p %s ref_count=%u size=%ld type=%s\n",
			indent, dentry, dentry->ddent,
			dentry->ddent_cnode, dentry->parent,
			dentry->ddent->name, dentry->ref_count,
			(long)dentry->size,
			S_ISDIR(dentry->ddent->mode) ? "dir" : 
			S_ISREG(dentry->ddent->mode) ? "reg" :
			"???");

	if (!S_ISDIR(dentry->ddent->mode))
		return;

	for (i = 0; i < dentry->size; i ++) {
		child = get_nth_dentry(dentry, i);
		if (IS_ERR(child)) {
			fprintf(stderr, "PANIC: get_nth_dentry(%p, %d): %s\n",
					dentry, i, strerror(PTR_ERR(child)));
			dump_ctree(&dentry->chunk_tree, indent, dump_dentries);
			fflush(stdout);
			abort();
		}
		dump_dentry_2(child, indent - 1);
		put_dentry(child);
	}
}

