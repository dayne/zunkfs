
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "zunkfs.h"
#include "zunkfs-tests.h"

#define NR_NODES	8 * DIGESTS_PER_CHUNK

#define panic(x...) do { \
	fprintf(stderr, "PANIC: " x); \
	abort(); \
} while(0)

static const char spaces[] = "                                                                                                                                                               ";
#define indent_start (spaces + sizeof(spaces) - 1)

struct chunk_tree_operations ctree_ops = {
	.free_private = free,
	.read_chunk   = read_chunk,
	.write_chunk  = write_chunk
};

int main(int argc, char **argv)
{
	struct chunk_tree ctree;
	struct chunk_node *cnode[NR_NODES];
	unsigned char root_digest[CHUNK_DIGEST_LEN];
	int i, err;

	zunkfs_log_fd = stdout;

	zero_chunk_digest(root_digest);

	err = init_chunk_tree(&ctree, 1, root_digest, &ctree_ops);
	if (err)
		panic("init_chunk_tree: %s\n", strerror(-err));

	printf("After init:\n");
	dump_ctree(&ctree, indent_start, NULL);

	for (i = 0; i < NR_NODES; i ++) {
		cnode[i] = get_nth_chunk(&ctree, i);
		if (IS_ERR(cnode[i]))
			panic("get_chunk_nr(%d): %s\n", i,
					strerror(PTR_ERR(cnode[i])));
		printf("[%d] = %p\n", i, cnode[i]);
	}

	printf("\nAfter inserting %d nodes:\n", i);
	dump_ctree(&ctree, indent_start, NULL);

	for (i = 0; i < NR_NODES; i ++)
		put_chunk_node(cnode[i]);

	printf("\nAfter putting %d nodes:\n", i);
	dump_ctree(&ctree, indent_start, NULL);

	for (i = 0; i < NR_NODES; i ++) {
		cnode[i] = get_nth_chunk(&ctree, i);
		if (IS_ERR(cnode[i]))
			panic("get_chunk_nr(%d): %s\n", i,
					strerror(PTR_ERR(cnode[i])));
		printf("[%d] = %p\n", i, cnode[i]);
	}

	printf("\nAfter getting %d nodes:\n", i);
	dump_ctree(&ctree, indent_start, NULL);

	return 0;
}

