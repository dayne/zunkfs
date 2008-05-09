
#define FUSE_USE_VERSION	26
#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <fuse.h>
#include <fuse_opt.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <pthread.h>
#include <ctype.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/mman.h>
#include <libgen.h>

#include "zunkfs.h"
#include "chunk-db.h"
#include "utils.h"
#include "dir.h"
#include "file.h"

static int zunkfs_getattr(const char *path, struct stat *stbuf)
{
	struct dentry *dentry;
	int dir_as_file = 0;

	TRACE("%s\n", path);

	dentry = find_dentry(path, &dir_as_file);
	if (IS_ERR(dentry))
		return -PTR_ERR(dentry);

	memset(stbuf, 0, sizeof(struct stat));

	lock(&dentry->mutex);

	memcpy(&stbuf->st_ino, dentry->ddent->secret_digest, sizeof(ino_t));
	stbuf->st_mode = dentry->ddent->mode;
	stbuf->st_nlink = 1;
	stbuf->st_uid = getuid();
	stbuf->st_gid = getgid();
	stbuf->st_size = dentry->size;
	stbuf->st_atime = dentry->mtime;
	stbuf->st_mtime = dentry->mtime;
	stbuf->st_ctime = dentry->ddent->ctime;
	stbuf->st_blksize = 4096;
	stbuf->st_blocks = (dentry->size + 4095) / 4096;

	if (dir_as_file) {
		stbuf->st_mode &= ~S_IFDIR;
		stbuf->st_mode |= S_IFREG;
		stbuf->st_size *= sizeof(struct disk_dentry);
	}

	unlock(&dentry->mutex);
	put_dentry(dentry);

	return 0;
}

static int zunkfs_readdir(const char *path, void *filldir_buf,
		fuse_fill_dir_t filldir, off_t offset,
		struct fuse_file_info *fuse_file)
{
	struct dentry *dentry;
	struct dentry *child;
	struct dentry *prev;
	unsigned i;
	int err;

	TRACE("%s\n", path);

	dentry = find_dentry(path, NULL);
	if (IS_ERR(dentry))
		return -PTR_ERR(dentry);

	err = -ENOTDIR;
	if (!S_ISDIR(dentry->ddent->mode))
		goto out;

	err = -ENOBUFS;
	if (filldir(filldir_buf, ".", NULL, 0) ||
			filldir(filldir_buf, "..", NULL, 0))
		goto out;

	/* racy, but should be OK */
	prev = NULL;
	for (i = 0; ; i ++) {
		child = get_nth_dentry(dentry, i);
		if (IS_ERR(child)) {
			err = -PTR_ERR(child);
			if (err == -ENOENT)
				err = 0;
			goto out;
		}
		TRACE("%s\n", (char *)child->ddent->name);
		if (filldir(filldir_buf, (char *)child->ddent->name, NULL, 0)) {
			err = -ENOBUFS;
			put_dentry(child);
			goto out;
		}
		if (prev)
			put_dentry(prev);
		prev = child;
	}
out:
	if (prev)
		put_dentry(prev);
	put_dentry(dentry);
	return err;
}

static int zunkfs_open(const char *path, struct fuse_file_info *fuse_file)
{
	struct open_file *ofile;

	TRACE("%s\n", path);

	ofile = open_file(path);
	if (IS_ERR(ofile))
		return -PTR_ERR(ofile);

	fuse_file->fh = (uint64_t)(uintptr_t)ofile;

	return 0;
}

static int zunkfs_read(const char *path, char *buf, size_t bufsz, off_t offset,
		struct fuse_file_info *fuse_file)
{
	struct open_file *ofile;

	TRACE("path=%p bufsz=%zd offset=%zd\n", path, bufsz, offset);

	ofile = (struct open_file *)(uintptr_t)fuse_file->fh;
	if (!ofile)
		return -EINVAL;

	return read_file(ofile, buf, bufsz, offset);
}

static int zunkfs_write(const char *path, const char *buf, size_t bufsz,
		off_t offset, struct fuse_file_info *fuse_file)
{
	struct open_file *ofile;

	TRACE("path=%p bufsz=%zd offset=%zd\n", path, bufsz, offset);

	ofile = (struct open_file *)(uintptr_t)fuse_file->fh;
	if (!ofile)
		return -EINVAL;

	return write_file(ofile, buf, bufsz, offset);
}

static int zunkfs_release(const char *path, struct fuse_file_info *fuse_file)
{
	struct open_file *ofile;

	TRACE("%s\n", path);

	ofile = (struct open_file *)(uintptr_t)fuse_file->fh;
	if (!ofile)
		return -EINVAL;

	fuse_file->fh = 0;
	return close_file(ofile);
}

static int zunkfs_mkdir(const char *path, mode_t mode)
{
	struct dentry *dentry;

	TRACE("%s %o\n", path, mode);

	dentry = create_dentry(path, mode | S_IFDIR);
	if (IS_ERR(dentry))
		return -PTR_ERR(dentry);
	put_dentry(dentry);
	return 0;
}

static int zunkfs_create(const char *path, mode_t mode,
		struct fuse_file_info *fuse_file)
{
	struct open_file *ofile;

	TRACE("%s mode=%o\n", path, mode);

	ofile = create_file(path, mode);
	if (IS_ERR(ofile))
		return -PTR_ERR(ofile);

	if (fuse_file)
		fuse_file->fh = (uint64_t)(uintptr_t)ofile;
	else
		close_file(ofile);

	return 0;
}

static int zunkfs_flush(const char *path, struct fuse_file_info *fuse_file)
{
	struct open_file *ofile;

	TRACE("%s\n", path);

	ofile = (struct open_file *)(uintptr_t)fuse_file->fh;
	if (!ofile)
		return -EINVAL;

	return flush_file(ofile);
}

static int zunkfs_unlink(const char *path)
{
	struct dentry *dentry;
	int err;

	TRACE("%s\n", path);

	dentry = find_dentry(path, NULL);
	err = -PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
		err = del_dentry(dentry);
		put_dentry(dentry);
	}

	return err;
}

static int zunkfs_rmdir(const char *path)
{
	struct dentry *dentry;
	int err;

	TRACE("%s\n", path);

	dentry = find_dentry(path, NULL);
	if (IS_ERR(dentry))
		return -PTR_ERR(dentry);

	err = -ENOTDIR;
	if (!S_ISDIR(dentry->ddent->mode))
		goto out;

	err = -EBUSY;
	if (dentry->size)
		put_dentry(dentry);

	err = del_dentry(dentry);
out:
	put_dentry(dentry);
	return err;
}

static int zunkfs_utimens(const char *path, const struct timespec tv[2])
{
	struct dentry *dentry;

	TRACE("%s\n", path);

	dentry = find_dentry(path, NULL);
	if (IS_ERR(dentry))
		return -PTR_ERR(dentry);

	lock(dentry->ddent_mutex);
	if (dentry->ddent->mtime != tv[1].tv_sec) {
		dentry->ddent->mtime = tv[1].tv_sec;
		dentry->ddent_cnode->dirty = 1;
	}
	unlock(dentry->ddent_mutex);
	put_dentry(dentry);

	return 0;
}

static int zunkfs_rename(const char *src, const char *dst)
{
	struct dentry *dentry;
	struct dentry *dst_parent;
	int err;

	dentry = find_dentry_parent(dst, &dst_parent, &dst);
	if (IS_ERR(dentry))
		return -PTR_ERR(dentry);

	err = -EEXIST;
	if (dentry)
		goto out;

	dentry = find_dentry(src, NULL);
	if (IS_ERR(dentry)) {
		err = -PTR_ERR(dentry);
		goto out;
	}

	err = rename_dentry(dentry, dst, dst_parent);
	put_dentry(dentry);
out:
	put_dentry(dst_parent);
	return err;
}

static int zunkfs_chmod(const char *path, mode_t mode)
{
	struct dentry *dentry;

	if ((mode & S_IFMT) != 0)
		return -EINVAL;

	dentry = find_dentry(path, NULL);
	if (IS_ERR(dentry))
		return -PTR_ERR(dentry);

	dentry_chmod(dentry, mode & ~S_IFMT);
	put_dentry(dentry);

	return 0;
}

static struct fuse_operations zunkfs_operations = {
	.getattr	= zunkfs_getattr,
	.readdir	= zunkfs_readdir,
	.open		= zunkfs_open,
	.read		= zunkfs_read,
	.write		= zunkfs_write,
	.release	= zunkfs_release,
	.mkdir		= zunkfs_mkdir,
	.create		= zunkfs_create,
	.flush		= zunkfs_flush,
	.unlink		= zunkfs_unlink,
	.utimens	= zunkfs_utimens,
	.rmdir		= zunkfs_rmdir,
	.rename		= zunkfs_rename,
	.chmod		= zunkfs_chmod
};

static void set_root_file(const char *fs_descr)
{
	static DECLARE_MUTEX(root_mutex);
	struct disk_dentry *root_ddent;
	int err, fd;

	fd = open(fs_descr, O_RDWR|O_CREAT, 0600);
	if (fd < 0) {
		ERROR("open(%s): %s\n", fs_descr, strerror(errno));
		exit(-1);
	}

	root_ddent = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
			MAP_SHARED, fd, 0);
	if (root_ddent == MAP_FAILED) {
		ERROR("mmap(%s): %s\n", fs_descr, strerror(errno));
		exit(-2);
	}

	if (root_ddent->name[0] == '\0') {
		namcpy(root_ddent->name, "/");

		root_ddent->mode = S_IFDIR | S_IRWXU;
		root_ddent->size = 0;
		root_ddent->ctime = time(NULL);
		root_ddent->mtime = time(NULL);

		err = random_chunk_digest(root_ddent->secret_digest);
		if (err < 0) {
			ERROR("random_chunk_digest: %s\n", strerror(-err));
			exit(-3);
		}

		memcpy(root_ddent->digest, root_ddent->secret_digest,
				CHUNK_DIGEST_LEN);
	} else if (root_ddent->name[0] != '/' || root_ddent->name[1]) {
		ERROR("Bad superblock.\n");
		exit(-4);
	}

	err = set_root(root_ddent, &root_mutex);
	if (err) {
		ERROR("Failed to set root: %s\n", strerror(-err));
		exit(-5);
	}
}

enum {
	OPT_HELP,
	OPT_LOG,
	OPT_CHUNK_DB
};

static struct fuse_opt zunkfs_opts[] = {
	FUSE_OPT_KEY("--help", OPT_HELP),
	FUSE_OPT_KEY("-h", OPT_HELP),
	FUSE_OPT_KEY("--log=%s", OPT_LOG),
	FUSE_OPT_KEY("--chunk-db=%s", OPT_CHUNK_DB),
	FUSE_OPT_END
};

static const char *prog = NULL;

static void usage(void)
{
	/* FIXME: Need to play nicely with FUSE's --help. */
	fprintf(stderr, "Usage: %s [options] root_ddent mountpt\n", prog);
	fprintf(stderr, "\t--log=[level,]<file|stderr|stdout>\n");
	fprintf(stderr, "\t\tlevel is one of (E)rror, (W)arning, (T)race\n");
	fprintf(stderr, "\t--chunk-db=<rw|ro>,<dbspec>\n");
	fprintf(stderr, "\n");
}

static int opt_proc(void *data, const char *arg, int key,
		struct fuse_args *args)
{
	static unsigned root_set = 0;
	int err;

	switch(key) {
	case OPT_HELP:
		usage();
		return 1;
	case OPT_LOG:
		if (zunkfs_log_fd) {
			fprintf(stderr, "Log file specified more than once.\n");
			return -1;
		}
		arg += 6;
		if (arg[1] == ',') {
			if (!strchr("EWT", arg[0]))
				return -1;
			zunkfs_log_level = arg[0];
			arg += 2;
		}
		if (!strcmp(arg, "stderr"))
			zunkfs_log_fd = stderr;
		else if (!strcmp(arg, "stdout"))
			zunkfs_log_fd = stdout;
		else
			zunkfs_log_fd = fopen(arg, "w");
		return 0;
	case OPT_CHUNK_DB:
		arg += 11;
		if (!strncmp(arg, "ro,", 3))
			err = add_chunkdb(CHUNKDB_RO, arg + 3);
		else if (!strncmp(arg, "rw,wt,", 6))
			err = add_chunkdb(CHUNKDB_RW|CHUNKDB_WT, arg + 6);
		else if (!strncmp(arg, "rw,", 3))
			err = add_chunkdb(CHUNKDB_RW, arg + 3);
		else
			return -1;
		if (err) {
			fprintf(stderr, "Failed to add chunkdb %s: %s\n", arg,
					strerror(-err));
			return -1;
		}
		return 0;
	default:
		if (arg[0] == '-' || root_set)
			return 1;
		set_root_file(arg);
		root_set = 1;
		return 0;
	}
}

int main(int argc, char **argv)
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	int err;

	prog = basename(argv[0]);

	if (fuse_opt_parse(&args, NULL, zunkfs_opts, opt_proc)) {
		usage();
		return -1;
	}

	err = fuse_main(args.argc, args.argv, &zunkfs_operations, NULL);
	if (!err)
		flush_root();
	return err;
}

