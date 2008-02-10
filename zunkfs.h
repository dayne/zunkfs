#ifndef __ZUNKFS_H__
#define __ZUNKFS_H__

#ifndef CHUNK_SIZE
#define CHUNK_SIZE		(1UL << 16)
#endif

#define CHUNK_DIGEST_LEN	20
#define DIGESTS_PER_CHUNK	(CHUNK_SIZE / CHUNK_DIGEST_LEN)

/*
 * Logging
 */
void __zprintf(char level, const char *funct, int line, const char *fmt, ...);

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

/*
 * Linux-ish pointer error handling.
 */
extern void *const __errbuf;

#define MAX_ERRNO	256

static inline void *__ERR_PTR(int err, const char *funct, int line)
{
	assert(err >= 0 && err < MAX_ERRNO);
	zprintf('E', funct, line, "%s\n", strerror(err));
	return (void *)(__errbuf + err);
}

#define ERR_PTR(err) __ERR_PTR(err, __FUNCTION__, __LINE__)

static inline int PTR_ERR(const void  *ptr)
{
	return ptr - __errbuf;
}

static inline int IS_ERR(const void *ptr)
{
	return ptr >= __errbuf && ptr < __errbuf + MAX_ERRNO;
}
/*
 * write_chunk() updates 'digest' field.
 */
int write_chunk(const unsigned char *chunk, unsigned char *digest);
int read_chunk(unsigned char *chunk, const unsigned char *digest);
void zero_chunk_digest(unsigned char *digest);

int verify_chunk(const unsigned char *chunk, const unsigned char *digest);

/*
 * chunk garbage collection.
 */
void ref_chunk(const unsigned char *digest);
void unref_chunk(const unsigned char *digest);

/*
 * Mutex wrappers
 */
static inline void lock(pthread_mutex_t *m)
{
	int err = pthread_mutex_lock(m);
	assert(err == 0);
}

static inline void unlock(pthread_mutex_t *m)
{
	int err = pthread_mutex_unlock(m);
	assert(err == 0);
}

static inline int trylock(pthread_mutex_t *m)
{
	int err = pthread_mutex_trylock(m);
	assert(err == 0 || err == EBUSY);
	return !err;
}

#define DECLARE_MUTEX(mtx) \
	pthread_mutex_t mtx = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP

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

/*
 * Directory/path stuff.
 */

/* I'd like disk_dentry to fit into 256 bytes. */
#define DDENT_NAME_MAX	(256 - 44)

struct disk_dentry {
	uint8_t digest[CHUNK_DIGEST_LEN]; // 20
	uint32_t mode;                    // 24
	uint64_t size;                    // 32
	uint32_t ctime;                   // 40
	uint32_t mtime;                   // 44
	uint8_t name[DDENT_NAME_MAX];     // 256
};

#define namcpy(dst, src)	strcpy((char *)(dst), src)
#define namcmp(nam, str, len)	strncmp((char *)nam, str, len)
#define DIRENTS_PER_CHUNK	(CHUNK_SIZE / sizeof(struct disk_dentry))

struct dentry {
	struct disk_dentry *ddent;
	struct chunk_node *ddent_cnode;
	struct dentry *parent;
	unsigned ref_count;
	struct chunk_tree chunk_tree;
};

struct dentry *get_nth_dentry(struct dentry *parent, unsigned nr);
void put_dentry(struct dentry *dentry);
struct dentry *add_dentry(struct dentry *parent, const char *name, mode_t mode);
int del_dentry(struct dentry *dentry);

struct dentry *find_dentry_parent(const char *path, struct dentry **pparent,
		const char **name);

static inline struct dentry *find_dentry(const char *path)
{
	return find_dentry_parent(path, NULL, NULL) ?: ERR_PTR(ENOENT);
}

int set_root(struct disk_dentry *ddent);

/*
 * Misc...
 */
#define container_of(ptr, type, memb) \
	((type *)((unsigned long)(ptr) - (unsigned long)&((type *)0)->memb))

#endif

