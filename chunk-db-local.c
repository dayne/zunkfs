
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "zunkfs.h"
#include "chunk-db.h"
#include "utils.h"

static int local_read_chunk(unsigned char *chunk, const unsigned char *digest,
		void *db_info)
{
	char *chunk_dir = db_info;
	int err, fd, len, n;
	char *path;

	err = asprintf(&path, "%s/%s", chunk_dir, digest_string(digest));
	if (err < 0)
		return -errno;

	TRACE("path=%s\n", path);

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

	return CHUNK_SIZE;
}

static int local_write_chunk(const unsigned char *chunk, 
		const unsigned char *digest, void *db_info)
{
	char *chunk_dir = db_info;
	int err, fd, len, n;
	char *path;

	err = asprintf(&path, "%s/%s", chunk_dir, digest_string(digest));
	if (err < 0)
		return -errno;

	TRACE("path=%s\n", path);

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

static struct chunk_db *local_chunkdb_ctor(int mode, const char *spec)
{
	struct chunk_db *cdb;
	struct stat stbuf;
	int err;

	if (strncmp(spec, "dir:", 4))
		return NULL;

	TRACE("mode=%d spec=%s\n", mode, spec);

	err = stat(spec+4, &stbuf);
	if (err == -1)
		return ERR_PTR(errno);
	if (!S_ISDIR(stbuf.st_mode))
		return ERR_PTR(ENOTDIR);
	if (access(spec+4, R_OK | (mode == CHUNKDB_RW ? W_OK : 0)))
		return ERR_PTR(errno);

	cdb = malloc(sizeof(struct chunk_db) + strlen(spec+4) + 1);
	if (!cdb)
		return ERR_PTR(ENOMEM);

	cdb->db_info = (void *)(cdb + 1);
	strcpy(cdb->db_info, spec+4);

	cdb->read_chunk = local_read_chunk;
	cdb->write_chunk = (mode == CHUNKDB_RW) ? local_write_chunk : NULL;

	return cdb;
}

static struct chunk_db_type local_chunkdb_type = {
	.ctor = local_chunkdb_ctor,
	.help =
"   dir:<path>              Chunks are stored in specified directory.\n"
};

static void __attribute__((constructor)) init_chunkdb_local(void)
{
	register_chunkdb(&local_chunkdb_type);
}

