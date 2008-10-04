
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

static LIST_HEAD(chunkdb_types);
static LIST_HEAD(chunkdb_list);

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

void register_chunkdb(struct chunk_db_type *type)
{
	list_add_tail(&type->type_entry, &chunkdb_types);
}

int add_chunkdb(const char *spec)
{
	struct chunk_db_type *type;
	struct chunk_db *cdb;
	int mode;

	if (!strncmp(spec, "ro,", 3)) {
		mode = CHUNKDB_RO;
		spec += 3;
	} else if (!strncmp(spec, "rw,", 3)) {
		mode = CHUNKDB_RW;
		spec += 3;
	} else {
		TRACE("Ugh. You forgot the mode! (ro/rw)\n");
		return -EINVAL;
	}

	if (mode == CHUNKDB_RW) {
		for (;;) {
			if (!strncmp(spec, "wt,", 3)) {
				mode |= CHUNKDB_WT;
				spec += 3;
			}  else if (!strncmp(spec, "nc,", 3)) {
				mode |= CHUNKDB_NC;
				spec += 3;
			} else
				break;
		}
	}

	list_for_each_entry(type, &chunkdb_types, type_entry) {
		cdb = type->ctor(mode, spec);
		if (cdb)
			goto found;
	}

	return -ENOENT;
found:
	if (IS_ERR(cdb))
		return -PTR_ERR(cdb);

	list_add_tail(&cdb->db_entry, &chunkdb_list);

	cdb->mode = mode;

	return 0;
}

void help_chunkdb(void)
{
	struct chunk_db_type *type;
	
	list_for_each_entry(type, &chunkdb_types, type_entry)
		if (type->help)
			fprintf(stderr, "%s\n", type->help);
}

int read_chunk(unsigned char *chunk, const unsigned char *digest)
{
	struct chunk_db *cdb;
	int len;

	list_for_each_entry(cdb, &chunkdb_list, db_entry) {
		if (cdb->read_chunk) {
			len = cdb->read_chunk(chunk, digest, cdb->db_info);
			if (len > 0 && verify_chunk(chunk, digest))
				goto cache_chunk;
		}
	}

	TRACE("chunk not found: %s\n", digest_string(digest));
	return -EIO;
cache_chunk:
	for (;;) {
		cdb = list_prev_entry(cdb, db_entry);
		if (&cdb->db_entry == &chunkdb_list)
			break;
		if (cdb->write_chunk && !(cdb->mode & CHUNKDB_NC))
			cdb->write_chunk(chunk, digest, cdb->db_info);
	}

	return len;
}

int write_chunk(const unsigned char *chunk, unsigned char *digest)
{
	struct chunk_db *cdb;
	int n, ret;

	digest_chunk(chunk, digest);

	TRACE("digest=%s\n", digest_string(digest));

	ret = -EIO;
	list_for_each_entry(cdb, &chunkdb_list, db_entry) {
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


