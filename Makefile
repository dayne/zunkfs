ifndef LIBEVENT_PREFIX
LIBEVENT_PREFIX=.
endif

CFLAGS=-Wall -g -I$(LIBEVENT_PREFIX)/include
LDFLAGS=-L$(LIBEVENT_PREFIX)/lib -levent -lcrypto -lssl

TARGETS=zunkdb test-client base64-test

all: $(TARGETS)

zunkdb: main.o base64.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test-client: client.o base64.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

base64-test: base64-test.o base64.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGETS) *.o

