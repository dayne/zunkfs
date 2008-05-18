
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>

#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "zunkfs.h"
#include "chunk-db.h"
#include "utils.h"

static chunkdb_ctor *ctor_list = NULL;
static int ctor_count = 0;

static struct chunk_db **chunkdb_list = NULL;
static int chunkdb_count = 0;

static inline int cmp_digest(const unsigned char *a, const unsigned char *b)
{
	return memcmp(a, b, CHUNK_DIGEST_LEN);
}

static inline unsigned char *digest_chunk(const unsigned char *chunk, 
		unsigned char *digest)
{
	SHA1(chunk, CHUNK_SIZE, digest);
	return digest;
}

#define INT_CHUNK_SIZE	((CHUNK_SIZE + sizeof(int) - 1) / sizeof(int))

int random_chunk_digest(unsigned char *digest)
{
	int i, chunk_data[INT_CHUNK_SIZE] = {0};

	for (i = 0; i < INT_CHUNK_SIZE; i ++)
		chunk_data[i] = rand();

	return write_chunk((void *)chunk_data, digest);
}

void register_chunkdb(chunkdb_ctor ctor)
{
	int n = ctor_count ++;

	ctor_list = realloc(ctor_list, ctor_count * sizeof(chunkdb_ctor));
	if (!ctor_list)
		panic("Failed to resize list of chunk database types.\n");

	ctor_list[n] = ctor;
}

int add_chunkdb(const char *spec)
{
	struct chunk_db *cdb;
	int i, n, mode;

	if (!strncmp(spec, "ro,", 3)) {
		mode = CHUNKDB_RO;
		spec += 3;
	} else if (!strncmp(spec, "rw,wt,", 6)) {
		mode = CHUNKDB_RW|CHUNKDB_WT;
		spec += 6;
	} else if (!strncmp(spec, "rw,", 3)) {
		mode = CHUNKDB_RW;
		spec += 3;
	} else
		return -EINVAL;

	for (i = 0; i < ctor_count; i ++) {
		cdb = ctor_list[i](mode, spec);
		if (cdb)
			goto found;
	}

	return -ENOENT;
found:
	if (IS_ERR(cdb))
		return -PTR_ERR(cdb);

	n = chunkdb_count ++;
	chunkdb_list = realloc(chunkdb_list,
			chunkdb_count * sizeof(struct chunk_db *));
	if (!chunkdb_list)
		panic("Failed to resize list of chunk databases.\n");

	cdb->mode = mode;
	chunkdb_list[n] = cdb;

	return 0;
}

int read_chunk(unsigned char *chunk, const unsigned char *digest)
{
	struct chunk_db *cdb;
	int i, len;

	for (i = 0; i < chunkdb_count; i ++) {
		cdb = chunkdb_list[i];
		if (cdb->read_chunk) {
			len = cdb->read_chunk(chunk, digest, cdb->db_info);
			if (len > 0 && verify_chunk(chunk, digest))
				goto cache_chunk;
		}
	}

	TRACE("chunk not found: %s\n", digest_string(digest));
	return -EIO;
cache_chunk:
	while (i--) {
		cdb = chunkdb_list[i];
		if (cdb->write_chunk)
			cdb->write_chunk(chunk, digest, cdb->db_info);
	}

	return len;
}

int write_chunk(const unsigned char *chunk, unsigned char *digest)
{
	struct chunk_db *cdb;
	int i, n, ret;

	digest_chunk(chunk, digest);

	TRACE("digest=%s\n", digest_string(digest));

	ret = -EIO;
	for (i = 0; i < chunkdb_count; i ++) {
		cdb = chunkdb_list[i];
		if (cdb->write_chunk) {
			n = cdb->write_chunk(chunk, digest, cdb->db_info);
			if (n > ret)
				ret = n;
			if (ret > 0 && (cdb->mode & CHUNKDB_WT) == 0)
				return ret;
		}
	}

	return ret;
}


