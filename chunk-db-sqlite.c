
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sqlite3.h>

#include "zunkfs.h"
#include "chunk-db.h"
#include "utils.h"
#include "mutex.h"

/*
 * CREATE TABLE chunk (
 * 	hash CHAR(20) PRIMARY KEY UNIQUE,
 * 	data BLOB
 * );
 */

struct db_info {
	sqlite3 *db;
	struct mutex mutex;
};

#define lock_db(db) lock(&(db)->mutex)
#define unlock_db(db) unlock(&(db)->mutex)

static int write_chunk_sqlite(const unsigned char *chunk,
		const unsigned char *digest, void *db_info_ptr)
{
	static const char sql[] =
		"INSERT OR IGNORE INTO chunk(hash, data) VALUES(?,?)";
	struct db_info *db_info = db_info_ptr;
	sqlite3_stmt *stmt;
	int err;

	lock_db(db_info);

	err = sqlite3_prepare(db_info->db, sql, -1, &stmt, 0);
	if (err != SQLITE_OK) {
		ERROR("sqlite3_prepare failed: %s\n",
				sqlite3_errmsg(db_info->db));
		unlock_db(db_info);
		return -EIO;
	}

	sqlite3_bind_text(stmt, 1, digest_string(digest), -1, SQLITE_STATIC);
	sqlite3_bind_blob(stmt, 2, chunk, CHUNK_SIZE, SQLITE_STATIC);

	err = sqlite3_step(stmt);
	assert(err != SQLITE_ROW);

	if (sqlite3_finalize(stmt) != SQLITE_OK) {
		ERROR("sqlite3_finalize failed: %s\n",
				sqlite3_errmsg(db_info->db));
		unlock_db(db_info);
		return -EIO;
	}

	unlock_db(db_info);
	return CHUNK_SIZE;
}

static int read_chunk_sqlite(unsigned char *chunk, const unsigned char *digest,
		void *db_info_ptr)
{
	static const char sql[] = "SELECT data FROM chunk WHERE hash = ?";
	struct db_info *db_info = db_info_ptr;
	sqlite3_stmt *stmt;
	int err, ret = -EIO;

	lock_db(db_info);
	err = sqlite3_prepare(db_info->db, sql, -1, &stmt, 0);
	if (err != SQLITE_OK) {
		ERROR("sqlite3_prepare failed: %d\n",
				sqlite3_errmsg(db_info->db));
		unlock_db(db_info);
		return -EIO;
	}

	TRACE("%s\n", digest_string(digest));

	sqlite3_bind_text(stmt, 1, digest_string(digest), -1, SQLITE_STATIC);

	err = sqlite3_step(stmt);
	if (err != SQLITE_ROW) {
		ERROR("sqlite3_step failed: %s\n",
				sqlite3_errmsg(db_info->db));
	} else if (sqlite3_column_bytes(stmt, 0) != CHUNK_SIZE) {
		ERROR("sqlite3 query returned %d bytes instead of %d.\n",
				sqlite3_column_bytes(stmt, 0), CHUNK_SIZE);
	} else {
		TRACE("sqlite3 query got chunk.\n");
		memcpy(chunk, sqlite3_column_blob(stmt, 0), CHUNK_SIZE);
		ret = CHUNK_SIZE;
	}

	sqlite3_finalize(stmt);
	unlock_db(db_info);

	return ret;
}

static struct chunk_db *sqlite_chunkdb_ctor(int mode, const char *spec)
{
	struct chunk_db *cdb;
	struct db_info *db_info;
	int err;

	if (strncmp(spec, "sqlite:", 7))
		return NULL;

	cdb = malloc(sizeof(struct chunk_db) + sizeof(struct db_info));
	if (!cdb)
		return ERR_PTR(ENOMEM);

	db_info = cdb->db_info = (void *)(cdb + 1);
	init_mutex(&db_info->mutex);

	err = sqlite3_open(spec + 7, &db_info->db);
	if (err != SQLITE_OK) {
		fprintf(stderr, "Can't open SQLite database '%s': %s\n",
				spec + 7, sqlite3_errmsg(db_info->db));
		sqlite3_close(db_info->db);
		free(cdb);
		return ERR_PTR(EINVAL);
	}

	cdb->read_chunk = read_chunk_sqlite;
	cdb->write_chunk = (mode == CHUNKDB_RO) ? NULL : write_chunk_sqlite;

	return cdb;
}

static struct chunk_db_type sqlite_chunkdb_type = {
	.ctor = sqlite_chunkdb_ctor,
	.help =
"   sqlite:<database>       SQLite storage for chunks. Database schema:\n"
"                              CREATE TABLE chunk (\n"
"                                      hash CHAR(20) PRIMARY KEY UNIQUE,\n"
"                                      data BLOB\n"
"                              );\n"
};

static void __attribute__((constructor)) init_sqlite_chunkdb(void)
{
	register_chunkdb(&sqlite_chunkdb_type);
}

