
#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <openssl/sha.h>
#include <arpa/inet.h> // ntohl and htonl

#include "utils.h"
#include "zunkfs.h"
#include "mutex.h"
#include "chunk-db.h"

#define MAX_INDEX		(CHUNK_SIZE / (sizeof(struct index)))
#define SPLIT_AT		((MAX_INDEX + 1) / 2)
#define INVALID_CHUNK_NR	0

/*
* Simple, 2-level btree. 2nd level is all leaf nodes. Should be 
* enough to store upto 4TB of data: MAX_INDEX * MAX_INDEX * CHUNK_SIZE =
* (8192 * 8192 * 65536B) = 4TB. Tho in reality it'll be about 1/2 of that
* due to leaf splitting.
*
* Note that 20-byte digests are converted to 4-byte hashes. This may lead
* to hash collisions. This is dealt with by allowing the same hash to
* appear multiple times in a leaf. Collisions are resolved at lookup.
*
* The first MAX_INDEX chunks are reserved for leaf index chunks. (512MB)
* Scan through these chunks to build the root node.
*/

struct index {
	uint32_t hash;
	uint32_t chunk_nr;
};

struct db {
	struct index root[MAX_INDEX];
	int fd;
	uint32_t next_nr;
	unsigned ro:1;
	struct mutex mutex;
};

static inline unsigned char *__map_chunk(struct db *db, uint32_t nr,
		int extra_flags)
{
	void *chunk;

	chunk = mmap(NULL, CHUNK_SIZE, PROT_READ | (db->ro ? 0 : PROT_WRITE),
			MAP_SHARED|extra_flags, db->fd, (off_t)nr * CHUNK_SIZE);
	if (chunk == MAP_FAILED)
		return ERR_PTR(errno);

	return chunk;
}

#ifndef MAP_NOCACHE /* OSX flag */
#define MAP_NOCACHE 0
#endif

/*
 * Take some premature optimizations:
 * - don't prolong caching of the chunk
 * - ask the OS to prefault the chunk, as it'll be used soon
 */
static inline void *map_chunk(struct db *db, uint32_t nr)
{
	if (nr >= db->next_nr)
		return ERR_PTR(EINVAL);

#ifdef MAP_POPULATE /* Linux flag */
	return __map_chunk(db, nr, MAP_POPULATE|MAP_NOCACHE);
#else
	void *chunk = __map_chunk(db, nr, MAP_NOCACHE);
	if (!IS_ERR(chunk))
		posix_madvise(chunk, CHUNK_SIZE, POSIX_MADV_WILLNEED);
	return chunk;
#endif
}

static inline void unmap_chunk(void *chunk)
{
	int error = munmap(chunk, CHUNK_SIZE);
	assert(error == 0);
}

/* used for sorting entries in the root index */
static int compar_root_index(const void *a, const void *b)
{
	const struct index *i = a, *j = b;
	assert(i->hash != j->hash);
	return i->hash < j->hash ? -1 : 1;
}

/*
* Only the leaf index nodes are store on disk. The root is generated
* at load time. The first entry in the root is special, in that
* it's hash is actually the # of leafs in the root, and the chunk_nr
* is *ALWAYS* 0. 
*/
static int build_root(struct db *db)
{
	uint32_t i;

	for (i = 1; i < MAX_INDEX; i ++) {
		ssize_t n = pread(db->fd, &db->root[i], sizeof(struct index),
				(off_t)i * CHUNK_SIZE);
		if (n < 0)
			return -errno;
		assert(n == sizeof(struct index));
		if (db->root[i].chunk_nr == INVALID_CHUNK_NR)
			break;
		db->root[i].hash = ntohl(db->root[i].hash);
		db->root[i].chunk_nr = ntohl(db->root[i].chunk_nr);
	}

	/*
	 * entries on disk are not sorted
	 */
	qsort(db->root + 1, i - 1, sizeof(struct index), compar_root_index);

	db->root[0].hash = i;
	db->root[0].chunk_nr = 0;

	return 0;
}

static int hash_insert(struct db *db, uint32_t hash, uint32_t chunk_nr)
{
	struct index *root = db->root;
	struct index *leaf;
	struct index *split;
	int i, split_at, leaf_nr;

	/* XXX: this may need to become a binary search */
	for (leaf_nr = 1; leaf_nr < root[0].hash; leaf_nr ++)
		if (hash < root[leaf_nr].hash)
			break;

	if (root[0].hash == MAX_INDEX)
		return -ENOSPC;

	leaf = map_chunk(db, root[leaf_nr - 1].chunk_nr);
	if (IS_ERR(leaf))
		return -PTR_ERR(leaf);

	/* XXX: this may need to become a binary search */
	for (i = 0; i < MAX_INDEX; i ++) {
		if (leaf[i].chunk_nr == INVALID_CHUNK_NR)
			break;
		if (hash < ntohl(leaf[i].hash))
			break;
	}

	if (leaf[MAX_INDEX-1].chunk_nr != INVALID_CHUNK_NR)
		goto split_leaf;

do_insert:
	memmove(leaf + i + 1, leaf + i, sizeof(*leaf) * (MAX_INDEX - i - 1));
	leaf[i].hash = htonl(hash);
	leaf[i].chunk_nr = htonl(chunk_nr);
	unmap_chunk(leaf);
	return 0;
split_leaf:
	/*
	 * Be smart where to split. If a hash repeats, make sure that
	 * all it stays in the same leaf.
	 */
	for (split_at = SPLIT_AT; split_at != MAX_INDEX; split_at ++)
		if (leaf[split_at].hash != leaf[split_at-1].hash)
			goto split_here;
	for (split_at = SPLIT_AT-1; split_at > 0; split_at --)
		if (leaf[split_at].hash != leaf[split_at-1].hash)
			goto split_here;
	unmap_chunk(leaf);
	return -ENOSPC;
split_here:
	split = map_chunk(db, root[0].hash);
	if (IS_ERR(split)) {
		unmap_chunk(leaf);
		return -PTR_ERR(split);
	}

	memcpy(split, leaf + split_at, sizeof(*leaf) * (MAX_INDEX - split_at));
	memset(leaf + split_at, 0, sizeof(*leaf) * (MAX_INDEX - split_at));

	memmove(root + leaf_nr + 1, root + leaf_nr, sizeof(*root) *
			(root[0].hash - leaf_nr));

	root[leaf_nr].hash = ntohl(split[0].hash);
	root[leaf_nr].chunk_nr = root[0].hash;

	root[0].hash ++;

	if (i > split_at) {
		unmap_chunk(leaf);
		leaf = split;
		i -= split_at;
	} else
		unmap_chunk(split);

	goto do_insert;
}

unsigned char *lookup_chunk(struct db *db, const unsigned char *digest)
{
	struct index *root = db->root;
	struct index *leaf;
	uint32_t hash = *(uint32_t *)digest;
	int i, leaf_nr;
	unsigned char *chunk;

	/* XXX: this may need to become a binary search */
	for (leaf_nr = 1; leaf_nr < root[0].hash; leaf_nr ++)
		if (hash < root[i].hash)
			break;

	leaf = map_chunk(db, root[leaf_nr - 1].chunk_nr);
	if (IS_ERR(leaf))
		return (void *)leaf;

	for (i = 0; i < MAX_INDEX; i ++) {
		if (leaf[i].chunk_nr == INVALID_CHUNK_NR)
			break;
		if (hash < ntohl(leaf[i].hash))
			break;
		if (hash == ntohl(leaf[i].hash)) {
			chunk = map_chunk(db, ntohl(leaf[i].chunk_nr));
			if (IS_ERR(chunk))
				goto out;
			if (verify_chunk(chunk, digest))
				goto out;
			unmap_chunk(chunk);
		}
	}
	chunk = NULL;
out:
	unmap_chunk(leaf);
	return chunk;
}

static int file_read_chunk(unsigned char *chunk, const unsigned char *digest,
		void *db_info)
{
	struct db *db = db_info;
	unsigned char *db_chunk;
	int error;

	lock(&db->mutex);
	db_chunk = lookup_chunk(db, digest);
	if (!db_chunk)
		error = -ENOENT;
	else if (IS_ERR(db_chunk))
		error = -PTR_ERR(db_chunk);
	else {
		memcpy(chunk, db_chunk, CHUNK_SIZE);
		unmap_chunk(db_chunk);
		error = CHUNK_SIZE;
	}
	unlock(&db->mutex);

	return error;
}

static int file_write_chunk(const unsigned char *chunk,
		const unsigned char *digest, void *db_info)
{
	struct db *db = db_info;
	unsigned char *db_chunk;
	int error = CHUNK_SIZE;

	lock(&db->mutex);
	db_chunk = lookup_chunk(db, digest);
	if (db_chunk) {
		if (IS_ERR(db_chunk))
			goto db_chunk_error;
		goto out;
	}

	/*
	 * When adding a new chunk, the file needs to be resized, otherwise
	 * any access to the chunk will cause a SIGBUS. 
	 */
	if (ftruncate(db->fd, ((off_t)db->next_nr + 1) * CHUNK_SIZE)) {
		error = -errno;
		goto out;
	}

	db_chunk = __map_chunk(db, db->next_nr, 0);
	if (IS_ERR(db_chunk))
		goto db_chunk_error;

	memcpy(db_chunk, chunk, CHUNK_SIZE);

	error = hash_insert(db, *(uint32_t *)digest, db->next_nr);
	if (error)
		goto out;

	error = CHUNK_SIZE;
	db->next_nr ++;
out:
	unmap_chunk(db_chunk);
	unlock(&db->mutex);
	return error;
db_chunk_error:
	unlock(&db->mutex);
	return -PTR_ERR(db_chunk);
}

static int file_chunkdb_ctor(const char *spec, struct chunk_db *chunk_db)
{
	const char *path = spec;
	struct db *db = chunk_db->db_info;
	struct stat st;
	int error;

	init_mutex(&db->mutex);

	db->ro = (chunk_db->mode == CHUNKDB_RO);
	db->fd = open(path, db->ro ? O_RDONLY : O_RDWR|O_CREAT, 0644);
	if (db->fd < 0)
		return -errno;

	if (fstat(db->fd, &st))
		goto set_error;

	db->next_nr = st.st_size / CHUNK_SIZE;
	if (db->next_nr < MAX_INDEX) {
		if (ftruncate(db->fd, CHUNK_SIZE * MAX_INDEX))
			goto set_error;
		db->next_nr = MAX_INDEX;
	}

	error = build_root(db);
	if (error)
		goto error;

#if HAVE_POSIX_FADVISE
	/*
	 * Tell the OS that it doesn't eed to do read-ahead on this file.
	 */
	posix_fadvise(db->fd, 0, 0, POSIX_FADV_RANDOM);
#endif

	return 0;
set_error:
	error = -errno;
error:
	close(db->fd);
	return error;
}

static struct chunk_db_type file_chunkdb_type = {
	.spec_prefix = "file:",
	.info_size = sizeof(struct db),
	.ctor = file_chunkdb_ctor,
	.read_chunk = file_read_chunk,
	.write_chunk = file_write_chunk,
	.help = 
"   file:<path>             Use an (almost) flat file for storing chunks.\n"
"                           The first 512MB of the file are reserved for\n"
"                           an index of the chunks. With this index, the file\n"
"                           can store upto 4TB of data in chunks.\n"
};

REGISTER_CHUNKDB(file_chunkdb_type);

