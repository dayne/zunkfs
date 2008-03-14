
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

static char chunk_dir[PATH_MAX];
static const char *fetch_cmd = NULL;

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

static int fetch_chunk(unsigned char *chunk, const unsigned char *digest)
{
	char chunk_name[CHUNK_DIGEST_STRLEN+1];
	int err;
	int fd[2];
	int pid;
	int len;
	int n;

	if  (!fetch_cmd)
		return -EIO;

	__digest_string(digest, chunk_name);

	TRACE("chunk=%s using %s\n", chunk_name, fetch_cmd);

	err = pipe(fd);
	if (err) {
		ERROR("pipe: %s\n", strerror(errno));
		return -EIO;
	}

	pid = fork();
	if (pid < 0) {
		ERROR("fork: %s\n", strerror(errno));
		close(fd[0]);
		close(fd[1]);
		return -EIO;
	}

	if (pid) {
		int status;

		close(fd[1]);

		for (len = 0; len < CHUNK_SIZE; ) {
			n = read(fd[0], chunk + len, CHUNK_SIZE - len);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				WARNING("read: %s\n", strerror(errno));
				err = -errno;
				close(fd[1]);
				kill(pid, 9);
				waitpid(pid, NULL, 0);
				return -EIO;
			}
			if (!n)
				break;
			len += n;
		}

		close(fd[0]);
		
		err = waitpid(pid, &status, 0);
		if (err < 0) {
			ERROR("waidpid: %s\n", strerror(errno));
			return -EIO;
		}
		if (!WIFEXITED(status)) {
			ERROR("Fetcher died unexpectedly.\n");
			return -EIO;
		}
		if (WEXITSTATUS(status)) {
			ERROR("Fetcher returned %d\n", WEXITSTATUS(status));
			return -EIO;
		}
		if (!verify_chunk(chunk, digest)) {
			ERROR("Chunk failed verification\n");
			return -EIO;
		}

		TRACE("len=%d", len);

		return len;
	}

	close(fd[0]);

	err = dup2(fd[1], STDOUT_FILENO);
	if (err < 0) {
		err = errno;
		ERROR("stdout redirection failed: %s\n", strerror(err));
		exit(-errno);
	}

	if (zunkfs_log_fd) {
		err = dup2(fileno(zunkfs_log_fd), STDERR_FILENO);
		if (err < 0) {
			err = errno;
			ERROR("stderr redirection failed: %s\n", strerror(err));
			exit(-errno);
		}
	}

	execl(fetch_cmd, fetch_cmd, chunk_dir, chunk_name, NULL);

	err = errno;

	ERROR("\"%s %s %s\" failed: %s\n", fetch_cmd, chunk_dir, chunk_name,
			strerror(err));

	exit(-err);

	/* prevent compiler warnings */
	return 0;
}

int read_chunk(unsigned char *chunk, const unsigned char *digest)
{
	int err, fd, len, n;
	char *path;

	err = asprintf(&path, "%s/%s", chunk_dir, digest_string(digest));
	if (err < 0)
		return -errno;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		int err = errno;
		free(path);
		if (err == ENOENT)
			return fetch_chunk(chunk, digest);
		WARNING("%s: %s\n", path, strerror(err));
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

void set_fetch_cmd(const char *cmd)
{
	fetch_cmd = cmd;
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

