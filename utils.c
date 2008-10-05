
#define _GNU_SOURCE

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "utils.h"
#include "mutex.h"

FILE *zunkfs_log_fd = NULL;
char zunkfs_log_level = 0;

int set_logging(const char *params)
{
	if (zunkfs_log_fd)
		return -EALREADY;

	if (params[1] == ',') {
		switch(params[0]) {
		case 'E':
			zunkfs_log_level = ZUNKFS_ERROR;
			break;
		case 'W':
			zunkfs_log_level = ZUNKFS_WARNING;
			break;
		case 'T':
			zunkfs_log_level = ZUNKFS_TRACE;
			break;
		default:
			return -EINVAL;
		}
		params += 2;
	}
	if (!strcmp(params, "stderr"))
		zunkfs_log_fd = stderr;
	else if (!strcmp(params, "stdout"))
		zunkfs_log_fd = stdout;
	else
		zunkfs_log_fd = fopen(params, "w");

	return zunkfs_log_fd ? 0 : -errno;
}

void __zprintf(char level, const char *function, int line, const char *fmt, ...)
{
	static DECLARE_MUTEX(log_mutex);
	const char *level_str = NULL;
	va_list ap;

	if (level == ZUNKFS_WARNING)
		level_str = "WARN: ";
	else if (level == ZUNKFS_ERROR)
		level_str = "ERR:  ";
	else if (level == ZUNKFS_TRACE)
		level_str = "TRACE:";
	else
		abort();

	lock(&log_mutex);
	if (zunkfs_log_fd == stderr)
		fflush(stdout);
	fprintf(zunkfs_log_fd, "%lx %s %s:%d: ",
			((unsigned long)pthread_self()) >> 8,
			level_str, function, line);

	va_start(ap, fmt);
	vfprintf(zunkfs_log_fd, fmt, ap);
	va_end(ap);

	fflush(zunkfs_log_fd);

	unlock(&log_mutex);
}

void *const __errptr;

static void __attribute__((constructor)) util_init(void)
{
	void *errptr = mmap(NULL, (MAX_ERRNO + 4095) & ~4095, PROT_NONE,
			MAP_PRIVATE|MAP_ANON, -1, 0);
	if (errptr == MAP_FAILED) {
		fprintf(stderr, "errptr: %s\n", strerror(errno));
		exit(-1);
	}
	memcpy((void *)&__errptr, &errptr, sizeof(void *));
}

size_t __attribute__((weak)) strnlen(const char *str, size_t max)
{
	size_t len;
	for (len = 0; len < max && str[len]; len ++)
		;
	return len;
}

int __attribute__((weak)) fls(int i)
{
	int j = 0;
	while (i) {
		i >>= 1;
		j ++;
	}
	return j;
}

struct sockaddr_in *__string_sockaddr_in(const char *str,
		struct sockaddr_in *sa)
{
	char *addr_str;
	char *port;

	assert(sa != NULL);
	assert(str != NULL);

	memset(sa, 0, sizeof(struct sockaddr_in));

	addr_str = alloca(strlen(str) + 1);
	if (!addr_str)
		return NULL;

	strcpy(addr_str, str);

	port = strchr(addr_str, ':');
	if (!port)
		return NULL;

	*port++ = 0;
	
	sa->sin_family = AF_INET;
	sa->sin_port = htons(atoi(port));
	sa->sin_addr.s_addr = INADDR_ANY;

	if (*addr_str && !inet_aton(addr_str, &sa->sin_addr))
		return NULL;

	return sa;
}

