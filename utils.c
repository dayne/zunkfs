
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

#include "utils.h"
#include "mutex.h"

FILE *zunkfs_log_fd = NULL;
char zunkfs_log_level = 0;

void __zprintf(char level, const char *function, int line, const char *fmt, ...)
{
	static DECLARE_MUTEX(log_mutex);
	const char *level_str = NULL;
	va_list ap;

	if (level == 'W')
		level_str = "WARN: ";
	else if (level == 'E')
		level_str = "ERR:  ";
	else if (level == 'T')
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

#if ZUNKFS_OS == Darwin
size_t strnlen(const char *str, size_t max)
{
	size_t len;
	for (len = 0; len < max && str[len]; len ++)
		;
	return len;
}
#endif

