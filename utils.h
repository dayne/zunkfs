#ifndef __ZUNKFS_UTIL_H__
#define __ZUNKFS_UTIL_H__

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

extern size_t strnlen(const char *s, size_t maxlen);

/*
 * Logging
 */
void __zprintf(char level, const char *funct, int line, const char *fmt, ...);

extern FILE *zunkfs_log_fd;
extern char zunkfs_log_level;

#define zprintf(level, function, line, fmt...) ({ \
	int ___ret = 0; \
	if (zunkfs_log_fd && (level) <= zunkfs_log_level) { \
		int ___saved_errno = errno; \
		__zprintf(level, function, line, fmt); \
		errno = ___saved_errno; \
		___ret = 1; \
	} \
	___ret; \
})

#define WARNING(x...) zprintf('W', __FUNCTION__, __LINE__, x)
#define ERROR(x...)   zprintf('E', __FUNCTION__, __LINE__, x)
#define TRACE(x...)   zprintf('T', __FUNCTION__, __LINE__, x)

#define panic(x...) do { \
	if (!zprintf('E', __FUNCTION__, __LINE__, x)) \
		fprintf(stderr, x); \
	abort(); \
} while(0)

#define COMPILER_ASSERT(cond, cond_name) \
static inline void __attribute__((unused)) COMPILER_ASSERT_##cond_name(void) { \
	switch(0) { \
	case (cond): \
	case 0: \
		break; \
	} \
}

/*
 * Linux-ish pointer error handling.
 */
extern void *const __errptr;

#define MAX_ERRNO	256

#ifndef NDEBUG
#include <string.h>

static inline void *__ERR_PTR(int err, const char *funct, int line)
{
	if (err > 0 && err < MAX_ERRNO) {
		zprintf('E', funct, line, "%s\n", strerror(err));
		return (void *)(__errptr + err);
	}
	return NULL;
}

static inline int __PTR_ERR(const void *ptr, const char *funct, int line)
{
	int err = (ptr - __errptr);
	if (err > 0 && err < MAX_ERRNO)
		zprintf('E', funct, line, "%s\n", strerror(err));
	return err;
}

#define ERR_PTR(err) __ERR_PTR(err, __FUNCTION__, __LINE__)
#define PTR_ERR(ptr) __PTR_ERR(ptr, __FUNCTION__, __LINE__)
#else
static inline void *ERR_PTR(int err)
{
	return (void *)(__errptr + err);
}

static inline int PTR_ERR(const void  *ptr)
{
	return ptr - __errptr;
}
#endif

static inline int IS_ERR(const void *ptr)
{
	return ptr >= __errptr && ptr < __errptr + MAX_ERRNO;
}

/*
 * Misc...
 */
#define container_of(ptr, type, memb) \
	((type *)((unsigned long)(ptr) - (unsigned long)&((type *)0)->memb))

#endif

