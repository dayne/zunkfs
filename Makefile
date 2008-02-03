FUSE_CFLAGS=$(shell pkg-config fuse --cflags) -D_FILE_OFFSET_BITS=64
FUSE_LIBS=$(shell pkg-config fuse --libs)
CFLAGS=-g -Wall $(FUSE_CFLAGS)
LDFLAGS=-lssl $(FUSE_LIBS)

all: zunkfs 

zunkfs: chunk-tree.o fuse.o chunk-ops.o
	$(CC) -o $@ $^ $(LDFLAGS) -lsqlite3

clean:
	@rm -f zunkfs *.o *.out *.log

