
#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "zunkfs.h"
#include "zunkfs-tests.h"

#define panic(x...) do { \
	fprintf(stderr, "PANIC: " x); \
	abort(); \
} while(0)

static const char spaces[] = "                                                                                                                                                               ";
#define indent_start (spaces + sizeof(spaces) - 1)

static void test1(void);
static void test2(void);

int main(int argc, char **argv)
{
	struct disk_dentry root_ddent;
	DECLARE_MUTEX(root_mutex);
	int err;

	fprintf(stderr, "DIRENTS_PER_CHUNK=%lu\n",
			(unsigned long)DIRENTS_PER_CHUNK);

	zunkfs_log_fd = stdout;

	err = init_disk_dentry(&root_ddent);
	if (err < 0)
		panic("init_disk_dentry: %s\n", strerror(-err));

	namcpy(root_ddent.name, "/");

	root_ddent.mode = S_IFDIR | S_IRWXU;
	root_ddent.size = 0;
	root_ddent.ctime = time(NULL);
	root_ddent.mtime = time(NULL);

	err = set_root(&root_ddent, &root_mutex);
	if (err)
		panic("set_root: %s\n", strerror(-err));

	if (0)
		test1();
	if (1)
		test2();

	return 0;
}

char *d_path(const char *prefix, const struct dentry *dentry)
{
	char *npath = NULL;
	char *path;
	int err;

	if (!dentry->parent) {
		path = strdup("/");
		assert(path != NULL);
		return path;
	}

	err = asprintf(&path, "/%s", dentry->ddent->name);
	assert(err != -1);

	while ((dentry = dentry->parent)) {
		if (!dentry->parent)
			break;
		err = asprintf(&npath, "/%s%s", dentry->ddent->name, path);
		assert(err != -1);
		free(path);
		path = npath;
	}

	if (prefix) {
		err = asprintf(&npath, "%s%s", prefix, path);
		assert(err != -1);
		free(path);
		path = npath;
	}

	return path;
}

static void test1(void)
{
	struct dentry *root;
	struct dentry *foo;
	struct dentry *bar;
	int err;

	root = find_dentry("/");
	if (IS_ERR(root))
		panic("find_dentry(/): %s\n", strerror(PTR_ERR(root)));

	printf("after getting root:\n");
	dump_dentry(root, indent_start);

	foo = add_dentry(root, "foo", S_IFREG | S_IRWXU);
	if (IS_ERR(foo))
		panic("add_dentry(foo): %s\n", strerror(PTR_ERR(foo)));

	printf("after adding foo:\n");
	dump_dentry(root, indent_start);

	bar = add_dentry(root, "bar", S_IFREG | S_IRWXU);
	if (IS_ERR(bar))
		panic("del_dentry(bar): %s\n", strerror(PTR_ERR(bar)));

	printf("after adding bar:\n");
	dump_dentry(root, indent_start);

	err = del_dentry(bar);
	if (err)
		panic("del(bar): %s\n", strerror(-err));

	put_dentry(bar);
	printf("\nafter del(bar):\n");
	dump_dentry(root, indent_start);

	put_dentry(foo);
	printf("\nafter putting foo:\n");
	dump_dentry(root, indent_start);

	put_dentry(bar);
	put_dentry(foo);
	put_dentry(root);
}

/*
 * Create a directory hierarchy, based on /lib
 */
static void test2(void)
{
	struct dentry *root;
	struct dentry *curr;
	struct dentry *new;
	DIR *dir;
	struct dirent *de;
	int n = 0;

	struct dlist {
		struct dentry *dentry;
		struct dlist *next;
	} *dlist = NULL, **dtail = &dlist, *d;

	root = find_dentry("/");
	if (IS_ERR(root))
		panic("find_dentry(/): %s\n", strerror(PTR_ERR(root)));

	dir = opendir("/lib");
	if (!dir)
		panic("opendir(/lib'): %s\n", strerror(errno));

	curr = root;
again:
	while ((de = readdir(dir))) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (de->d_type == DT_DIR) {
			new = add_dentry(curr, de->d_name, S_IRWXU | S_IFDIR);
			if (IS_ERR(new)) {
				panic("dir::add_dentry(%s/%s): %s\n",
						curr->ddent->name,
						de->d_name,
						strerror(PTR_ERR(new)));
			}
			d = malloc(sizeof(struct dlist));
			assert(d != NULL);
			d->dentry = new;
			d->next = NULL;
			*dtail = d;
			dtail = &d->next;
			n ++;
		} else if (de->d_type == DT_REG) {
			new = add_dentry(curr, de->d_name, S_IRWXU | S_IFREG);
			if (IS_ERR(new)) {
				panic("reg::add_dentry(%s/%s): %s\n",
						curr->ddent->name,
						de->d_name,
						strerror(PTR_ERR(new)));
			}
			put_dentry(new);
			n ++;
		}
	}
	//put_dentry(curr);
	closedir(dir);

	if (dlist) {
		char *path;
		d = dlist;
		dlist = d->next;
		curr = d->dentry;
		free(d);
		path = d_path("/lib", curr);
		dir = opendir(path);
		if (!dir)
			panic("opendir(2, %s): %s\n", path, strerror(errno));
		//printf("\r%s                                        ", path);
		free(path);

		if (!dlist)
			dtail = &dlist;

		goto again;
	}
	printf("\n");

	dump_dentry_2(root, indent_start);
}

