
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "zunkfs.h"
#include "zunkfs-tests.h"

#define NR_NODES	8 * DIGESTS_PER_CHUNK

#define panic(x...) do { \
	fprintf(stderr, "PANIC: " x); \
	abort(); \
} while(0)

static const char spaces[] = "                                                                                                                                                               ";
#define indent_start (spaces + sizeof(spaces) - 1)

int main(int argc, char **argv)
{
	struct chunk_tree ctree;
	struct chunk_node *cnode[NR_NODES];
	unsigned char root_digest[CHUNK_DIGEST_LEN];
	int i, err;

	zunkfs_log_fd = stdout;

	zero_chunk_digest(root_digest);

	err = init_chunk_tree(&ctree, 1, root_digest);
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

