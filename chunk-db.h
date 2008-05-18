#ifndef __ZUNKFS_CHUNKDB_H__
#define __ZUNKFS_CHUNKDB_H__

/*
 * Chunk database.
 */
struct chunk_db {
	int (*read_chunk)(unsigned char *chunk, const unsigned char *digest,
			void *db_info);
	int (*write_chunk)(const unsigned char *chunk,
			const unsigned char *digest, void *db_info);
	int mode;
	void *db_info;
};

#define CHUNKDB_RO 0 /* read-only */
#define CHUNKDB_RW 1 /* read-write */
#define CHUNKDB_WT 2 /* write thru */

typedef struct chunk_db *(*chunkdb_ctor)(int mode, const char *spec);

void register_chunkdb(chunkdb_ctor ctor);
int add_chunkdb(const char *spec);

#endif

