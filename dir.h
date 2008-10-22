#ifndef __ZUNKFS_DIR_H__
#define __ZUNKFS_DIR_H__

#include <stdint.h>

#include "zunkfs.h"
#include "chunk-tree.h"
#include "mutex.h"
#include "utils.h"

#define DIR_AS_FILE	".super_secret_file"

/* I'd like disk_dentry to fit into 256 bytes. */
#define DDENT_NAME_MAX	(256 - 60)

struct disk_dentry {
	uint8_t digest[CHUNK_DIGEST_LEN];        // 20 20
	uint8_t secret_digest[CHUNK_DIGEST_LEN]; // 20 40
	uint16_t mode;                           //  2 42
	uint8_t flags;                           //  1 43
	uint8_t mtime_csec;                      //  1 44
	uint64_t size;                           //  8 52
	uint32_t ctime;                          //  4 56
	uint32_t mtime;                          //  4 60
	uint8_t name[DDENT_NAME_MAX];            // .. 256
} __attribute__((packed));

COMPILER_ASSERT(sizeof(struct disk_dentry) == 256, sizeof_disk_dentry_is_256);

#define namcpy(dst, src)	strcpy((char *)(dst), src)
#define namcmp(nam, str, len)	strncmp((char *)nam, str, len)
#define DIRENTS_PER_CHUNK	(CHUNK_SIZE / sizeof(struct disk_dentry))

COMPILER_ASSERT(DIRENTS_PER_CHUNK > 0, DIRENTS_PER_CHUNK_NOT_ZERO);

int init_disk_dentry(struct disk_dentry *ddent);

/*
 * Locking is a bit tricky, as ddent and ddent_cnode
 * belong to the parent dentry. So set ddent_mutex
 * to be ->parent->mutex (in 99% of the cases.)
 * The locking rules are:
 * 	lock dentry before ddent_mutex
 * ->ddent->digest	ddent_mutex
 * ->ddent->mode	ddent_mutex
 * ->ddent->size	ddent_mutex
 * ->ddent->ctime	ddent_mutex
 * ->ddent->mtime	ddent_mutex
 * ->ddent->name	ddent_mutex
 * ->ddent_cnode->dirty	ddent_mutex
 * ->ref_count 		ddent_mutex
 * ->chunk_tree		mutex
 * ->dirty              mutex
 * ->size               mutex
 * ->mtime		mutex
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
	unsigned dirty:1;
	/*
	 * mirror some ddent values
	 * here to simplify locking
	 */
	uint64_t size;
	struct timeval mtime;
};

void __put_dentry(struct dentry *dentry);
void put_dentry(struct dentry *dentry);

struct dentry *add_dentry(struct dentry *parent, const char *name, mode_t mode);
int del_dentry(struct dentry *dentry);
struct chunk_node *get_dentry_chunk(struct dentry *dentry, unsigned chunk_nr);

struct dentry *find_dentry_parent(const char *path, struct dentry **pparent,
		const char **name);

struct dentry *find_dentry(const char *path, int *dir_as_file);

struct dentry *create_dentry(const char *path, mode_t mode);

int rename_dentry(struct dentry *dentry, const char *new_name,
		struct dentry *new_parent);

void dentry_chmod(struct dentry *dentry, mode_t mode);

int set_root(struct disk_dentry *ddent, struct mutex *ddent_mutex);
void flush_root(void);

int scan_dir(struct dentry *dentry, int (*func)(struct dentry *, void *),
		void *scan_data);

int dup_disk_dentry(struct dentry *parent, const struct disk_dentry *src);

#endif

