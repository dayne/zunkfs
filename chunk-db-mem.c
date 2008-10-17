
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

	list_for_each_entry(cp, &cache->chunk_list, c_entry) {
		if (!memcmp(digest, cp->digest, CHUNK_DIGEST_LEN)) {
			TRACE("%s is a duplicate\n", digest_string(digest));
			goto found;
		}
	}

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

static int mem_chunkdb_ctor(const char *spec, struct chunk_db *chunk_db)
{
	struct cache *cache = chunk_db->db_info;

	if (!(chunk_db->mode & CHUNKDB_RW))
		return -EINVAL;

	list_head_init(&cache->chunk_list);
	init_mutex(&cache->mutex);

	cache->count = 0;
	cache->max = -1;

	if (spec[0]) {
		cache->max = atol(spec);
		if (!cache->max)
			cache->max = -1;
	}

	return 0;
}

static struct chunk_db_type mem_chunkdb_type = {
	.spec_prefix = "mem:",
	.info_size = sizeof(struct cache),
	.ctor = mem_chunkdb_ctor,
	.read_chunk = mem_read_chunk,
	.write_chunk = mem_write_chunk,
	.help =
"   mem:[max]               Dummy chunk database that stores all chunks in\n"
"                           memory. To limit memory usage, set max to\n"
"                           maximum number of chunks that can be cached.\n"
};

REGISTER_CHUNKDB(mem_chunkdb_type);
