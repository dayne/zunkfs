
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
#include "zunkfs.h"

FILE *zunkfs_log_fd = NULL;

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
	fprintf(zunkfs_log_fd, "%lx %s %s:%d: ",
			((unsigned long)pthread_self()) >> 8,
			level_str, function, line);

	va_start(ap, fmt);
	vfprintf(zunkfs_log_fd, fmt, ap);
	va_end(ap);

	fflush(zunkfs_log_fd);

	unlock(&log_mutex);
}

void *const __errbuf;

static void __attribute__((constructor)) util_init(void)
{
	void *errbuf = mmap(NULL, (MAX_ERRNO + 4095) & ~4095, PROT_NONE,
			MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (errbuf == MAP_FAILED) {
		fprintf(stderr, "errbuf: %s\n", strerror(errno));
		exit(-1);
	}
	memcpy((void *)&__errbuf, &errbuf, sizeof(void *));
}

