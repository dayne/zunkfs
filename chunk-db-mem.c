
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "utils.h"
#include "mutex.h"
#include "chunk-db.h"
#include "zunkfs.h"
#include "list.h"

struct chunk {
	unsigned char digest[CHUNK_DIGEST_LEN];
	unsigned char data[CHUNK_SIZE];
	struct list_head c_entry;
};

struct cache {
	struct list_head chunk_list;
	unsigned long count;
	unsigned long max;
	struct mutex mutex;
};

static int mem_read_chunk(unsigned char *chunk, const unsigned char *digest,
		void *db_info)
{
	struct cache *cache = db_info;
	struct chunk *cp;
	int ret = 0;

	lock(&cache->mutex);

	list_for_each_entry(cp, &cache->chunk_list, c_entry) {
		if (!memcmp(digest, cp->digest, CHUNK_DIGEST_LEN)) {
			memcpy(chunk, cp->data, CHUNK_SIZE);
			list_move(&cp->c_entry, &cache->chunk_list);
			ret = CHUNK_SIZE;
			break;
		}
	}

	unlock(&cache->mutex);

	return ret;
}

static int mem_write_chunk(const unsigned char *chunk,
		const unsigned char *digest, void *db_info)
{
	struct cache *cache = db_info;
	struct chunk *cp;
	int ret = 0;

	lock(&cache->mutex);

	list_for_each_entry(cp, &cache->chunk_list, c_entry)
		if (!memcmp(digest, cp->digest, CHUNK_DIGEST_LEN))
			goto found;

	ret = -ENOMEM;
	cp = malloc(sizeof(struct chunk));
	if (!cp)
		goto out;

	memcpy(cp->digest, digest, CHUNK_DIGEST_LEN);
	memcpy(cp->data, chunk, CHUNK_SIZE);

	list_add(&cp->c_entry, &cache->chunk_list);

	cache->count ++;
	if (cache->count > cache->max) {
		cp = list_entry(cache->chunk_list.prev, struct chunk, c_entry);
		list_del(&cp->c_entry);
		free(cp);
		cache->count --;
	}

found:
	ret = CHUNK_SIZE;
out:
	unlock(&cache->mutex);
	return ret;
}

static struct chunk_db *mem_chunkdb_ctor(int mode, const char *spec)
{
	struct chunk_db *cdb;
	struct cache *cache;

	if (strncmp(spec, "mem:", 4) || mode != CHUNKDB_RW)
		return NULL;

	cdb = malloc(sizeof(struct chunk_db) + sizeof(struct cache));
	if (!cdb)
		panic("Failed to allocate chunk_db.\n");

	cdb->db_info = (void *)(cdb + 1);
	cache = cdb->db_info;

	list_head_init(&cache->chunk_list);
	init_mutex(&cache->mutex);

	cache->count = 0;
	cache->max = -1;

	if (spec[4]) {
		cache->max = atol(spec + 4);
		if (!cache->max)
			cache->max = -1;
	}

	cdb->read_chunk = mem_read_chunk;
	cdb->write_chunk = (mode == CHUNKDB_RO) ? NULL : mem_write_chunk;

	return cdb;
}

static struct chunk_db_type mem_chunkdb_type = {
	.ctor = mem_chunkdb_ctor,
	.help =
"   mem:[max]               Dummy chunk database that stores all chunks in\n"
"                           memory. To limit memory usage, set max to\n"
"                           maximum number of chunks that can be cached.\n"
};

static void __attribute__((constructor)) init_chunkdb_mem(void)
{
	register_chunkdb(&mem_chunkdb_type);
}

