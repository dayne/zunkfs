
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sqlite3.h>

#include "zunkfs.h"
#include "chunk-db.h"
#include "utils.h"

/*
 * CREATE TABLE chunk (
 * 	hash CHAR(20) PRIMARY KEY UNIQUE,
 * 	data BLOB
 * );
 */

static int write_chunk_sqlite(const unsigned char *chunk,
		const unsigned char *digest, void *db_info)
{
	static const char sql[] = "INSERT INTO chunk(hash, data) VALUES(?,?)";
	sqlite3_stmt *stmt;
	int err;

	err = sqlite3_prepare(db_info, sql, -1, &stmt, 0);
	if (err != SQLITE_OK) {
		ERROR("sqlite3_prepare failed: %s\n", sqlite3_errmsg(db_info));
		return -EIO;
	}

	sqlite3_bind_text(stmt, 1, digest_string(digest), -1, SQLITE_STATIC);
	sqlite3_bind_blob(stmt, 2, chunk, CHUNK_SIZE, SQLITE_STATIC);

	err = sqlite3_step(stmt);
	assert(err != SQLITE_ROW);

	if (sqlite3_finalize(stmt) != SQLITE_OK) {
		ERROR("sqlite3_finalize failed: %s\n", sqlite3_errmsg(db_info));
		return -EIO;
	}

	return CHUNK_SIZE;
}

static int read_chunk_sqlite(unsigned char *chunk, const unsigned char *digest,
		void *db_info)
{
	static const char sql[] = "SELECT data FROM chunk WHERE hash = ?";
	sqlite3_stmt *stmt;
	int err, ret = -EIO;

	err = sqlite3_prepare(db_info, sql, -1, &stmt, 0);
	if (err != SQLITE_OK) {
		ERROR("sqlite3_prepare failed: %d\n", sqlite3_errmsg(db_info));
		return -EIO;
	}

	sqlite3_bind_text(stmt, 1, digest_string(digest), -1, SQLITE_STATIC);

	err = sqlite3_step(stmt);
	if (err != SQLITE_ROW) {
		ERROR("sqlite3_step failed: %s\n", sqlite3_errmsg(db_info));
	} else if (sqlite3_column_bytes(stmt, 0) != CHUNK_SIZE) {
		ERROR("sqlite3 query returned %d bytes instead of %d.\n",
				sqlite3_column_bytes(stmt, 0), CHUNK_SIZE);
	} else {
		memcpy(chunk, sqlite3_column_blob(stmt, 0), CHUNK_SIZE);
		ret = CHUNK_SIZE;
	}

	sqlite3_finalize(stmt);
	return ret;
}

static struct chunk_db *sqlite_chunkdb_ctor(int mode, const char *spec)
{
	struct chunk_db *cdb;
	sqlite3 *db_info;
	int err;

	if (strncmp(spec, "sqlite:", 7))
		return NULL;

	cdb = malloc(sizeof(struct chunk_db));
	if (!cdb)
		return ERR_PTR(ENOMEM);

	err = sqlite3_open(spec + 7, &db_info);
	if (err != SQLITE_OK) {
		fprintf(stderr, "Can't open SQLite database '%s': %s\n",
				spec + 7, sqlite3_errmsg(db_info));
		sqlite3_close(db_info);
		free(cdb);
		return ERR_PTR(EINVAL);
	}

	cdb->db_info = db_info;
	cdb->read_chunk = read_chunk_sqlite;
	cdb->write_chunk = (mode == CHUNKDB_RW) ? write_chunk_sqlite : NULL;

	return cdb;
}

static void __attribute__((constructor)) init_sqlite_chunkdb(void)
{
	register_chunkdb(sqlite_chunkdb_ctor);
}

