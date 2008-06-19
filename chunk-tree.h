#ifndef __CHUNK_TREE_H__
#define __CHUNK_TREE_H__

struct chunk_tree;

struct chunk_tree_operations {
	void (*free_private)(void *);
	int (*read_chunk)(unsigned char *chunk, const unsigned char *digest);
	int (*write_chunk)(const unsigned char *chunk, unsigned char *digest);
};

struct chunk_node {
	unsigned char chunk_data[CHUNK_SIZE];
	unsigned char *chunk_digest;
	struct chunk_node *parent;
	struct chunk_tree *ctree;
	unsigned dirty:1;
	unsigned ref_count;
	void *_private;
};

struct chunk_tree {
	struct chunk_node *root;
	unsigned nr_leafs;
	unsigned height;
	struct chunk_tree_operations *ops;
};

struct chunk_node *get_nth_chunk(struct chunk_tree *ctree, unsigned chunk_nr);
void put_chunk_node(struct chunk_node *cnode);

int init_chunk_tree(struct chunk_tree *ctree, unsigned nr_leafs,
		unsigned char *root_digest, struct chunk_tree_operations *ops);
void free_chunk_tree(struct chunk_tree *ctree);
int flush_chunk_tree(struct chunk_tree *ctree);

unsigned chunk_nr(const struct chunk_node *cnode);

#endif

