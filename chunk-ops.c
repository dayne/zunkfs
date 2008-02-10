
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include <openssl/sha.h>

#include "zunkfs.h"

#define CHUNK_CACHE_SIZE	1024

struct cached_chunk {
	struct cached_chunk *next;
	unsigned char chunk_digest[CHUNK_DIGEST_LEN];
	unsigned char chunk_data[CHUNK_SIZE];
};

static struct cached_chunk *chunk_cache[CHUNK_CACHE_SIZE] = {NULL};
static struct cached_chunk *zero_chunk = NULL;
static unsigned long nr_chunks = 0;

static inline unsigned long chunk_index(const unsigned char *digest)
{
	unsigned long hash = 0;
	int i;

	for (i = 0; i < CHUNK_DIGEST_LEN; i ++)
		hash = *digest++ + 31 * hash;

	return hash % CHUNK_CACHE_SIZE;
}

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

int verify_chunk(const unsigned char *chunk, const unsigned char *digest)
{
	unsigned char tmp_digest[CHUNK_DIGEST_LEN];
	return !cmp_digest(digest, digest_chunk(chunk, tmp_digest));
}

static inline int verify_cached_chunk(struct cached_chunk *cc)
{
	return verify_chunk(cc->chunk_data, cc->chunk_digest);
}

static struct cached_chunk *lookup_chunk(const unsigned char *chunk_digest)
{
	struct cached_chunk *cc, **ccp;

	ccp = &chunk_cache[chunk_index(chunk_digest)];
	while ((cc = *ccp)) {
		if (cmp_digest(chunk_digest, cc->chunk_digest)) {
			ccp = &cc->next;
			continue;
		}
		if (verify_cached_chunk(cc))
			return cc;
		WARNING("Corrupt chunk in cache!\n");
		*ccp = cc->next;
		free(cc);
	}

	return NULL;
}

static struct cached_chunk *cache_chunk(const unsigned char *data,
		const unsigned char *digest)
{
	struct cached_chunk *cc, **ccp;

	assert(verify_chunk(data, digest));

	cc = malloc(sizeof(struct cached_chunk));
	if (!cc)
		return NULL;

	memcpy(cc->chunk_data, data, CHUNK_SIZE);
	memcpy(cc->chunk_digest, digest, CHUNK_DIGEST_LEN);
	
	ccp = &chunk_cache[chunk_index(digest)];
	cc->next = *ccp;
	*ccp = cc;

	nr_chunks ++;

	return cc;
}

static inline char half_byte2char(unsigned char half_byte)
{
	return ((char *)"0123456789abcdef")[half_byte];
}

const char *digest2string(const unsigned char *digest)
{
	static char buf[CHUNK_DIGEST_LEN * 2 + 1];
	char *ptr;
	int i;

	for (i = 0, ptr = buf; i < CHUNK_DIGEST_LEN; i ++) {
		*ptr++ = half_byte2char(digest[i] & 0xf);
		*ptr++ = half_byte2char((digest[i] >> 4) & 0xf);
	}
	*ptr = 0;

	return buf;
}

int read_chunk(unsigned char *chunk, const unsigned char *digest)
{
	struct cached_chunk *cc;

	cc = lookup_chunk(digest);
	if (!cc)
		return -EIO;

	memcpy(chunk, cc->chunk_data, CHUNK_SIZE);
	return CHUNK_SIZE;
}

int write_chunk(const unsigned char *chunk, unsigned char *digest)
{
	digest_chunk(chunk, digest);

	if (lookup_chunk(digest) || cache_chunk(chunk, digest))
		return CHUNK_SIZE;

	return -EIO;
}

void zero_chunk_digest(unsigned char *digest)
{
	memcpy(digest, zero_chunk->chunk_digest, CHUNK_DIGEST_LEN);
}

static void __attribute__((constructor)) init_chunk_ops(void)
{
	/*
	 * special case -- "zero" chunk
	 */
	unsigned char zero_chunk_digest[CHUNK_DIGEST_LEN];
	unsigned char zero_chunk_data[CHUNK_SIZE] = {0};
	struct cached_chunk *cc;

	digest_chunk(zero_chunk_data, zero_chunk_digest);

	cc = cache_chunk(zero_chunk_data, zero_chunk_digest);
	assert(cc != NULL);

	zero_chunk = cc;
}

static void __attribute__((destructor)) fini_chunk_ops(void)
{
	fprintf(stderr, "nr_chunks: %lu\n", nr_chunks);
}

