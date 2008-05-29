
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "utils.h"
#include "mutex.h"
#include "chunk-db.h"
#include "zunkfs.h"

struct chunk {
	unsigned char digest[CHUNK_DIGEST_LEN];
	unsigned char data[CHUNK_SIZE];
	struct chunk *next;
};

static struct chunk *head_chunk = NULL;
static DECLARE_MUTEX(cdb_mutex);

static int mem_read_chunk(unsigned char *chunk, const unsigned char *digest,
		void *db_info)
{
	struct chunk *cp;
	int ret = 0;

	lock(&cdb_mutex);

	for (cp = head_chunk; cp; cp = cp->next) {
		if (!memcmp(digest, cp->digest, CHUNK_DIGEST_LEN)) {
			memcpy(chunk, cp->data, CHUNK_SIZE);
			ret = CHUNK_SIZE;
			break;
		}
	}

	unlock(&cdb_mutex);

	return ret;
}

static int mem_write_chunk(const unsigned char *chunk,
		const unsigned char *digest, void *db_info)
{
	struct chunk *cp, **cpp;
	int ret = 0;

	lock(&cdb_mutex);

	for (cpp = &head_chunk; (cp = *cpp); cpp = &cp->next)
		if (!memcmp(digest, cp->digest, CHUNK_DIGEST_LEN))
			goto found;

	ret = -ENOMEM;
	cp = malloc(sizeof(struct chunk));
	if (!cp)
		goto out;

	memcpy(cp->digest, digest, CHUNK_DIGEST_LEN);
	memcpy(cp->data, chunk, CHUNK_SIZE);
	cp->next = NULL;
	*cpp = cp;

found:
	ret = CHUNK_SIZE;
out:
	unlock(&cdb_mutex);
	return ret;
}

static struct chunk_db *mem_chunkdb_ctor(int mode, const char *spec)
{
	struct chunk_db *cdb;

	if (strncmp(spec, "mem:", 4) || mode != CHUNKDB_RW)
		return NULL;

	cdb = malloc(sizeof(struct chunk_db));
	if (!cdb)
		panic("Failed to allocate chunk_db.\n");
	cdb->read_chunk = mem_read_chunk;
	cdb->write_chunk = mem_write_chunk;

	return cdb;
}

static struct chunk_db_type mem_chunkdb_type = {
	.ctor = mem_chunkdb_ctor,
	//       0         1         2         3
	//       0123456789012345678901234567890
	.help =
"   mem:                    Dummy chunk database that stores all chunks in \n"
"                           memory.\n"
};

static void __attribute__((constructor)) init_chunkdb_mem(void)
{
	register_chunkdb(&mem_chunkdb_type);
}

