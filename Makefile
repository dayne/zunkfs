FUSE_CFLAGS=$(shell pkg-config fuse --cflags)
FUSE_LIBS=$(shell pkg-config fuse --libs) 
LDFLAGS=-lssl -lsqlite3 $(FUSE_LIBS)
CFLAGS=-g -Wall $(FUSE_CFLAGS) -DZUNKFS_OS=$(OS)
OS=$(shell /usr/bin/env uname)

ifdef CHUNK_SIZE
CFLAGS+=-DCHUNK_SIZE=$(CHUNK_SIZE)
endif

ifeq ("$(OS)","Darwin")
LDFLAGS+=-lcrypto
LDFLAGS+=-framework CoreFoundation
endif

ifeq ("$(OS)","Linux")
FUSE_CFLAGS+=-D_FILE_OFFSET_BITS=64
endif

CORE_OBJS=chunk-tree.o \
	  chunk-db.o \
	  dir.o \
	  file.o \
	  utils.o \
	  mutex.o

DBTYPES=chunk-db-local.o \
	chunk-db-cmd.o \
	chunk-db-map.o \
	chunk-db-sqlite.o \
	chunk-db-mem.o

UNIT_TEST_OBJS=$(CORE_OBJS) unit-test-utils.o chunk-db-mem.o

FINAL_OBJS=zunkfs \
	   ctree-unit-test \
	   dir-unit-test \
	   file-unit-test \
	   zunkfs-list-ddents \
	   zunkfs-add-ddent

all: ${FINAL_OBJS}

tests: ctree-unit-test dir-unit-test file-unit-test

zunkfs: $(CORE_OBJS) $(DBTYPES) fuse.o
	$(CC) -o $@ $^ $(LDFLAGS)

ctree-unit-test: $(UNIT_TEST_OBJS) ctree-unit-test.o
	$(CC) $(CFLAGS) -o $@ $^  $(LDFLAGS)

dir-unit-test: $(UNIT_TEST_OBJS) dir-unit-test.o
	$(CC) $(CFLAGS) -o $@ $^  $(LDFLAGS)

file-unit-test: $(UNIT_TEST_OBJS) file-unit-test.o
	$(CC) $(CFLAGS) -o $@ $^  $(LDFLAGS)

zunkfs-list-ddents: $(CORE_OBJS) $(DBTYPES) zunkfs-list-ddents.o 
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

zunkfs-add-ddent: $(CORE_OBJS) $(DBTYPES) zunkfs-add-ddent.o 
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	@rm -f $(FINAL_OBJS) *.o *.out *.log core

