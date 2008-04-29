CFLAGS=-Wall -g
LDFLAGS=-levent -lcrypto -lssl

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

