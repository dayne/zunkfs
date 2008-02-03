#ifndef __ZUNKFS_H__
#define __ZUNKFS_H__

void __zprintf(char level, const char *function, int line, const char *fmt, ...);

extern FILE *zunkfs_log_fd;

#define zprintf(level, function, line, fmt...) do { \
	if (zunkfs_log_fd) { \
		int ___saved_errno = errno; \
		__zprintf(level, function, line, fmt); \
		errno = ___saved_errno; \
	} \
} while(0)

#define WARNING(x...) zprintf('W', __FUNCTION__, __LINE__, x)
#define ERROR(x...)   zprintf('E', __FUNCTION__, __LINE__, x)
#define TRACE(x...)   zprintf('T', __FUNCTION__, __LINE__, x)

#define CHUNK_SIZE		(1UL << 16)
#define CHUNK_DIGEST_LEN	20
#define DIGESTS_PER_CHUNK	(CHUNK_SIZE / CHUNK_DIGEST_LEN)

/*
 * write_chunk() updates 'digest' field.
 */
int __write_chunk(const unsigned char *chunk, unsigned char *digest,
		const char *caller);
int __read_chunk(unsigned char *chunk, const unsigned char *digest,
		const char *caller);
void zero_chunk_digest(unsigned char *digest);

#define write_chunk(chunk, digest) __write_chunk(chunk, digest, __FUNCTION__)
#define read_chunk(chunk, digest) __read_chunk(chunk, digest, __FUNCTION__)

/*
 * chunk garbage collection.
 */
void ref_chunk(const unsigned char *digest);
void unref_chunk(const unsigned char *digest);

/*
 * Mutex ops that save errno.
 */
#define lock_mutex(mtx) do { \
	int ___saved_errno = errno; \
	int ___err = pthread_mutex_lock(mtx); \
	assert(___err == 0); \
	errno = ___saved_errno; \
} while(0)

#define unlock_mutex(mtx) do { \
	int ___saved_errno = errno; \
	int ___err = pthread_mutex_unlock(mtx); \
	assert(___err == 0); \
	errno = ___saved_errno; \
} while(0)

#define trylock_mutex(mtx) ({ \
	int ___saved_errno = errno; \
	int ___err = pthread_mutex_trylock(mtx); \
	assert(___err == 0 || ___err == EBUSY); \
	errno = ___saved_errno; \
	!___err; \
})

#define DECLARE_MUTEX(mtx) pthread_mutex_t mtx = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP

struct chunk_node {
	unsigned char chunk_data[CHUNK_SIZE];
	unsigned char *chunk_digest;
	struct chunk_node *parent;
	unsigned dirty:1;
	unsigned ref_count;
	void **child;
};

struct chunk_tree {
	struct chunk_node *root;
	unsigned nr_chunks; // # of leaf chunks
	unsigned height;
};

struct chunk_node *get_chunk_nr(struct chunk_tree *ctree, unsigned chunk_nr);
void __put_chunk_node(struct chunk_node *cnode, const char *caller);

#define put_chunk_node(cnode) __put_chunk_node(cnode, __FUNCTION__)

int init_chunk_tree(struct chunk_tree *ctree, unsigned nr_chunks,
		unsigned char *root_digest);
void free_chunk_tree(struct chunk_tree *ctree);
int flush_chunk_tree(struct chunk_tree *ctree);

#endif

