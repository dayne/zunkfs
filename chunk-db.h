#ifndef __ZUNKFS_CHUNKDB_H__
#define __ZUNKFS_CHUNKDB_H__

#include "list.h"

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
	struct list_head db_entry;
};

typedef struct chunk_db *(*chunkdb_ctor)(int mode, const char *spec);

struct chunk_db_type {
	chunkdb_ctor ctor;
	/*
	 * Help string. Format is:
	 * <spec>   <description>.
	 * spec must be indented 3 spaces,
	 * and must not exceed 23 characters.
	 * A help line should not exceed 80 characters.
	 */
	const char *help;
	struct list_head type_entry;
};

#define CHUNKDB_RO 0 /* read-only */
#define CHUNKDB_RW 1 /* read-write */
#define CHUNKDB_WT 2 /* write thru */

void register_chunkdb(struct chunk_db_type *type);
int add_chunkdb(const char *spec);

void help_chunkdb(void);

#endif

