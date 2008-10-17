
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "zunkfs.h"
#include "chunk-db.h"
#include "utils.h"

typedef ssize_t (*xfer_fn)(int fd, void *buf, size_t len);

static int xfer_chunk(unsigned char *chunk, const unsigned char *digest,
		xfer_fn op, int orig_fd, void *db_info)
{
	const char *fetch_cmd = db_info;
	char chunk_name[CHUNK_DIGEST_STRLEN+1];
	int err;
	int fd[2];
	int pid;
	int len;
	int n;

	assert(fetch_cmd != NULL);

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
			n = op(fd[0], chunk + len, CHUNK_SIZE - len);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				WARNING("read: %s\n", strerror(errno));
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
		
		/*
		 * Don't worry about return values from waitpid(),
		 * as the IO is already completed.
		 */
		waitpid(pid, &status, 0);

		TRACE("len=%d", len);

		return len;
	}

	close(fd[0]);

	err = dup2(fd[1], orig_fd);
	if (err < 0) {
		ERROR("stdio redirection failed: %s\n", strerror(errno));
		exit(-errno);
	}

	if (zunkfs_log_fd) {
		err = dup2(fileno(zunkfs_log_fd), STDERR_FILENO);
		if (err < 0) {
			ERROR("stderr redirection failed: %s\n",
					strerror(errno));
			exit(-errno);
		}
	}

	execl(fetch_cmd, fetch_cmd, chunk_name, NULL);

	ERROR("\"%s %s\" failed: %s\n", fetch_cmd, chunk_name, strerror(err));
	exit(-errno);

	/* prevent compiler warnings */
	return 0;
}

static int cmd_read_chunk(unsigned char *chunk, const unsigned char *digest,
		void *db_info)
{
	return xfer_chunk(chunk, digest, (xfer_fn)read, STDOUT_FILENO, db_info);
}

static int cmd_write_chunk(const unsigned char *chunk,
		const unsigned char *digest, void *db_info)
{
	return xfer_chunk((unsigned char *)chunk, digest, 
			(xfer_fn)write, STDIN_FILENO, db_info);
}

static int cmd_chunkdb_ctor(const char *spec, struct chunk_db *cdb)
{
	TRACE("mode=0x%x spec=%s\n", cdb->mode, spec);

	if (access(spec, X_OK)) {
		WARNING("%s is not executable: %s\n", spec, strerror(errno));
		return -errno;
	}

	cdb->db_info = (void *)spec;

	return 0;
}

static struct chunk_db_type cmd_chunkdb_type = {
	.spec_prefix = "cmd:",
	.ctor = cmd_chunkdb_ctor,
	.read_chunk = cmd_read_chunk,
	.write_chunk = cmd_write_chunk,
	.help =
"   cmd:<command>           <command> is a full path to a program which takes\n"
"                           a chunk hash as its only argument, and outputs\n"
"                           the chunk to stdout.\n"
};

static void __attribute__((constructor)) init_chunkdb_cmd(void)
{
	register_chunkdb(&cmd_chunkdb_type);
}

