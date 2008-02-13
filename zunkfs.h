#ifndef __ZUNKFS_H__
#define __ZUNKFS_H__

#ifndef CHUNK_SIZE
#define CHUNK_SIZE		(1UL << 16)
#endif

#define CHUNK_DIGEST_LEN	20
#define CHUNK_DIGEST_STRLEN	(CHUNK_DIGEST_LEN * 2)
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
#define PANIC(x...) do { \
	zprintf('E', __FUNCTION__, __LINE__, x); \
	abort(); \
} while(0)

/*
 * Linux-ish pointer error handling.
 */
extern void *const __errbuf;

#define MAX_ERRNO	256

static inline void *__ERR_PTR(int err, const char *funct, int line)
{
	if (err > 0 && err < MAX_ERRNO) {
		zprintf('E', funct, line, "%s\n", strerror(err));
		return (void *)(__errbuf + err);
	}
	return NULL;
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
int random_chunk_digest(unsigned char *digest);

int verify_chunk(const unsigned char *chunk, const unsigned char *digest);

const char *__digest_string(const unsigned char *digest, char *strbuf);

#define digest_string(digest) \
	__digest_string(digest, alloca(CHUNK_DIGEST_STRLEN + 1))

/*
 * chunk garbage collection.
 */
void ref_chunk(const unsigned char *digest);
void unref_chunk(const unsigned char *digest);

/*
 * Mutex wrappers.
 */
struct mutex {
	pthread_mutex_t mutex;
	pthread_t owner;
};

#define INIT_MUTEX { \
	PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP, \
	(pthread_t)-1 \
}

#define DECLARE_MUTEX(name) \
	struct mutex name = INIT_MUTEX

void init_mutex(struct mutex *m);
void lock(struct mutex *m);
void unlock(struct mutex *m);
int trylock(struct mutex *m);

static inline int have_mutex(const struct mutex *m)
{
	return m->owner == pthread_self();
}

void locked_inc(unsigned *v, struct mutex *m);
void locked_dec(unsigned *v, struct mutex *m);

struct chunk_tree;

struct chunk_tree_operations {
	void (*free_private)(void *);
	int (*read_chunk)(unsigned char *chunk, const unsigned char *digest);
	int (*write_chunk)(const unsigned char *chunk, unsigned char *digest);
	int (*zero_digest)(struct chunk_tree *ctree, unsigned char *digest);
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
#define DDENT_NAME_MAX	(256 - 64)

struct disk_dentry {
	uint8_t digest[CHUNK_DIGEST_LEN];        // 20
	uint8_t secret_digest[CHUNK_DIGEST_LEN]; // 40
	uint32_t mode;                           // 44
	uint64_t size;                           // 52
	uint32_t ctime;                          // 60
	uint32_t mtime;                          // 64
	uint8_t name[DDENT_NAME_MAX];            // 256
};

#define namcpy(dst, src)	strcpy((char *)(dst), src)
#define namcmp(nam, str, len)	strncmp((char *)nam, str, len)
#define DIRENTS_PER_CHUNK	(CHUNK_SIZE / sizeof(struct disk_dentry))

int init_disk_dentry(struct disk_dentry *ddent);

/*
 * Locking is a bit tricky, as ddent and ddent_cnode
 * belong to the parent dentry. So set ddent_mutex
 * to be ->parent->mutex (in 99% of the cases.)
 * The locking rules are:
 * 	lock dentry before ddent_mutex
 * ->ddent->digest	ddent_mutex
 * ->ddent->mode	ddent_mutex
 * ->ddent->size	mutex, ddent_mutex
 * ->ddent->ctime	ddent_mutex
 * ->ddent->mtime	mutex, ddent_mutex
 * ->ddent->name	ddent_mutex
 * ->ddent_cnode->dirty	mutex, ddent_mutex
 * ->ref_count 		ddent_mutex
 * ->chunk_tree		mutex
 */
struct dentry {
	struct disk_dentry *ddent;
	struct chunk_node *ddent_cnode;
	struct mutex *ddent_mutex;
	struct dentry *parent;
	struct mutex mutex;
	unsigned ref_count;
	struct chunk_tree chunk_tree;
	unsigned char *secret_chunk;
};

struct dentry *get_nth_dentry(struct dentry *parent, unsigned nr);
void put_dentry(struct dentry *dentry);
struct dentry *add_dentry(struct dentry *parent, const char *name, mode_t mode);
int del_dentry(struct dentry *dentry);
struct chunk_node *get_dentry_chunk(struct dentry *dentry, unsigned chunk_nr);

struct dentry *find_dentry_parent(const char *path, struct dentry **pparent,
		const char **name);

static inline struct dentry *find_dentry(const char *path)
{
	return find_dentry_parent(path, NULL, NULL) ?: ERR_PTR(ENOENT);
}

int set_root(struct disk_dentry *ddent, struct mutex *ddent_mutex);

/*
 * Misc...
 */
#define container_of(ptr, type, memb) \
	((type *)((unsigned long)(ptr) - (unsigned long)&((type *)0)->memb))

#endif

