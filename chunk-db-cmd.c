
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

static int fetch_chunk(unsigned char *chunk, const unsigned char *digest,
		void *db_info)
{
	const char *fetch_cmd = db_info;
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

	execl(fetch_cmd, fetch_cmd, chunk_name, NULL);

	err = errno;
	ERROR("\"%s %s\" failed: %s\n", fetch_cmd, chunk_name, strerror(err));
	exit(-err);

	/* prevent compiler warnings */
	return 0;
}

static struct chunk_db *ext_chunkdb_ctor(int mode, const char *spec)
{
	struct chunk_db *cdb;

	if (strncmp(spec, "cmd:", 4))
		return NULL;

	TRACE("mode=%d spec=%s\n", mode, spec);

	if (mode != CHUNKDB_RO)
		return ERR_PTR(EINVAL);
	if (access(spec + 4, X_OK))
		return ERR_PTR(EACCES);

	cdb = malloc(sizeof(struct chunk_db) + strlen(spec + 4) + 1);
	if (!cdb)
		return ERR_PTR(ENOMEM);

	cdb->db_info = (void *)(cdb + 1);
	strcpy(cdb->db_info, spec + 4);

	cdb->read_chunk = fetch_chunk;
	cdb->write_chunk = NULL;

	return cdb;
}

static void __attribute__((constructor)) init_chunkdb_cmd(void)
{
	register_chunkdb(ext_chunkdb_ctor);
}

