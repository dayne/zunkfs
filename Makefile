FUSE_CFLAGS=$(shell pkg-config fuse --cflags) -D_FILE_OFFSET_BITS=64
FUSE_LIBS=$(shell pkg-config fuse --libs)
CFLAGS=-g -Wall $(FUSE_CFLAGS)
LDFLAGS=-lssl $(FUSE_LIBS)

ifdef CHUNK_SIZE
CFLAGS+=-DCHUNK_SIZE=$(CHUNK_SIZE)
endif

CORE_OBJS=chunk-tree.o \
	  chunk-ops.o \
	  dir.o \
	  utils.o

UNIT_TEST_OBJS=$(CORE_OBJS) unit-test-utils.o

FINAL_OBJS=zunkfs ctree-unit-test dir-unit-test

all: zunkfs 

zunkfs: $(CORE_OBJS) fuse.o
	$(CC) -o $@ $^ $(LDFLAGS) #-lsqlite3

ctree-unit-test: $(UNIT_TEST_OBJS) ctree-unit-test.o
	$(CC) -o $@ $^  $(LDFLAGS)

dir-unit-test: $(UNIT_TEST_OBJS) dir-unit-test.o
	$(CC) -o $@ $^  $(LDFLAGS)


clean:
	@rm -f $(FINAL_OBJS) *.o *.out *.log

