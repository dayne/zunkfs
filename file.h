#ifndef __ZUNKFS_FILE_H__
#define __ZUNKFS_FILE_H__

#include "zunkfs.h"

struct dentry;
struct chunk_node;

#define MIN_FILE_CHUNK_CACHE_SIZE	16

#if CHUNK_SIZE > 4096
#define FILE_CHUNK_CACHE_SIZE	(MIN_FILE_CHUNK_CACHE_SIZE * CHUNK_SIZE / 4096)
#else
#define FILE_CHUNK_CACHE_SIZE	MIN_FILE_CHUNK_CACHE_SIZE
#endif

struct open_file {
	struct dentry *dentry;
	struct chunk_node *ccache[FILE_CHUNK_CACHE_SIZE];
	unsigned ccache_index;
};

struct open_file *open_file(const char *path);
struct open_file *create_file(const char *path, mode_t mode);
int close_file(struct open_file *ofile);
int flush_file(struct open_file *ofile);
int read_file(struct open_file *ofile, char *buf, size_t bufsz, off_t offset);
int write_file(struct open_file *ofile, const char *buf, size_t len, off_t off);

#endif

