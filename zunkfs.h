#ifndef __ZUNKFS_H__
#define __ZUNKFS_H__

#ifndef CHUNK_SIZE
#define CHUNK_SIZE		(1UL << 16)
#endif

#define CHUNK_DIGEST_LEN	20
#define CHUNK_DIGEST_STRLEN	(CHUNK_DIGEST_LEN * 2)
#define DIGESTS_PER_CHUNK	(CHUNK_SIZE / CHUNK_DIGEST_LEN)

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

#endif

