
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

#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "zunkfs.h"

static unsigned long nr_reads = 0;
static unsigned long nr_writes = 0;
static char chunk_dir[PATH_MAX];

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

static inline char half_byte2char(unsigned char half_byte)
{
	return ((char *)"0123456789abcdef")[half_byte];
}

const char *__digest_string(const unsigned char *digest, char *strbuf)
{
	char *ptr;
	int i;

	for (i = 0, ptr = strbuf; i < CHUNK_DIGEST_LEN; i ++) {
		*ptr++ = half_byte2char(digest[i] & 0xf);
		*ptr++ = half_byte2char((digest[i] >> 4) & 0xf);
	}
	*ptr = 0;

	return strbuf;
}

int read_chunk(unsigned char *chunk, const unsigned char *digest)
{
	int err, fd, len, n;
	char *path;

	nr_reads ++;

	err = asprintf(&path, "%s/%s", chunk_dir, digest_string(digest));
	if (err < 0)
		return -errno;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		WARNING("%s: %s\n", path, strerror(errno));
		free(path);
		return -EIO;
	}
	free(path);

	len = 0;
	while (len < CHUNK_SIZE) {
		n = read(fd, chunk + len, CHUNK_SIZE - len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			err = -errno;
			WARNING("read %s: %s\n", path, strerror(errno));
			close(fd);
			return err;
		}
		len += n;
	}
	close(fd);

	if (!verify_chunk(chunk, digest)) {
		unsigned char tmp_digest[CHUNK_DIGEST_LEN];
		digest_chunk(chunk, tmp_digest);
		WARNING("Chunk in storage doesn't match digest! %s vs %s\n",
				digest_string(digest),
				digest_string(tmp_digest));
		return -EIO;
	}

	return CHUNK_SIZE;
}

int write_chunk(const unsigned char *chunk, unsigned char *digest)
{
	int err, fd, len, n;
	char *path;

	nr_writes ++;

	digest_chunk(chunk, digest);

	err = asprintf(&path, "%s/%s", chunk_dir, digest_string(digest));
	if (err < 0)
		return -errno;

	fd = open(path, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		WARNING("%s: %s\n", path, strerror(errno));
		free(path);
		return -EIO;
	}
	free(path);

	len = 0;
	while (len < CHUNK_SIZE) {
		n = write(fd, chunk + len, CHUNK_SIZE - len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			err = -errno;
			WARNING("%s: %s\n", path, strerror(errno));
			close(fd);
			return err;
		}
		len += n;
	}
	err = close(fd);
	if (err)
		return -errno;

	return CHUNK_SIZE;
}

#define INT_CHUNK_SIZE	((CHUNK_SIZE + sizeof(int) - 1) / sizeof(int))

int random_chunk_digest(unsigned char *digest)
{
	int i, chunk_data[INT_CHUNK_SIZE] = {0};

	for (i = 0; i < INT_CHUNK_SIZE; i ++)
		chunk_data[i] = rand();

	return write_chunk((void *)chunk_data, digest);
}

static void __attribute__((constructor)) init_chunk_ops(void)
{
	char cwd[PATH_MAX];
	int err;

	err = snprintf(chunk_dir, PATH_MAX, "%s/.chunks",
			getcwd(cwd, PATH_MAX));
	assert(err < PATH_MAX);

	err = mkdir(chunk_dir, S_IRWXU);
	if (err < 0 && errno != EEXIST) {
		PANIC("Failed to create .chunks directory: %s\n",
				strerror(errno));
	}
}

static void __attribute__((destructor)) fini_chunk_ops(void)
{
	fprintf(stderr, "nr_reads: %lu\n", nr_reads);
	fprintf(stderr, "nr_writes: %lu\n", nr_writes);
}

