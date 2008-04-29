
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <openssl/sha.h>

#include <event.h>
#include "base64.h"

#define VALUE_SIZE	65536

static unsigned char value[VALUE_SIZE];

static const char hex_digits[] = "0123456789abcdef";

static const char *__sha1_string(const void *buf, size_t len, char *string)
{
	char *ptr = string;
	unsigned char digest[SHA_DIGEST_LENGTH];
	int i;

	SHA1(buf, len, digest);

	for (i = 0; i < SHA_DIGEST_LENGTH; i ++) {
		*ptr++ = hex_digits[digest[i] & 0xf];
		*ptr++ = hex_digits[(digest[i] >> 4) & 0xf];
	}
	*ptr++ = 0;

	return string;
}

#define sha1_string(buf, len) \
	__sha1_string(buf, len, alloca(SHA_DIGEST_LENGTH * 2 + 1))

#define FIND_VALUE		"find_chunk"
#define FIND_VALUE_LEN		(sizeof(FIND_VALUE) - 1)
#define STORE_VALUE		"store_chunk"
#define STORE_VALUE_LEN		(sizeof(STORE_VALUE) - 1)
#define REQUEST_DONE		"request_done"
#define REQUEST_DONE_LEN	(sizeof(REQUEST_DONE)-1)

static void bev_read(struct bufferevent *bev, void *arg)
{
	const char *buf, *end;
	size_t len;
	char *msg;
	unsigned char *vbuf;

	buf = (const char *)EVBUFFER_DATA(bev->input);
	end = (const char *)evbuffer_find(bev->input, (u_char *)"\r\n", 2);

	if (!end)
		return;

	len = end - buf;
	msg = alloca(len + 1);
	assert(msg != NULL);

	memcpy(msg, buf, len);
	msg[len] = 0;

	evbuffer_drain(bev->input, len + 2);

	if (!strncmp(msg, STORE_VALUE, STORE_VALUE_LEN)) {
		msg += STORE_VALUE_LEN + 1;
		len -= STORE_VALUE_LEN - 1;

		vbuf = alloca(base64_size(len));
		assert(vbuf != NULL);

		len = base64_decode(msg, vbuf, base64_size(len));
		if (len != VALUE_SIZE) {
			fprintf(stderr, "Eek: expected %d, got %zu bytes.\n",
					VALUE_SIZE, len);
			return;
		}

		printf("%s %s\n", STORE_VALUE, sha1_string(vbuf, VALUE_SIZE));
	} else {
		printf("%s\n", msg);
	}
}

static void bev_error(struct bufferevent *bev, short what, void *arg)
{
	bufferevent_free(bev);
}

enum {
	SELF_TEST,
	FIND_CHUNK,
	STORE_CHUNK
};

static int valid_digest(const char *str)
{
	int i;

	for (i = 0; i < 2 * SHA_DIGEST_LENGTH; i ++, str ++)
		if (!*str || !strchr(hex_digits, *str))
			return 0;

	return !*str;
}

static char *prog;

static void usage(void)
{
	fprintf(stderr, "Usage: %s <store_chunk|find_chunk> [digest]\n",
			prog);

	exit(-1);
}

int main(int argc, char **argv)
{
	struct sockaddr_in addr;
	struct bufferevent *bev;
	struct evbuffer *buf;
	int i, sk;
	int test = SELF_TEST;
	const char *digest = NULL;

	prog = basename(argv[0]);

	if (argc >= 2) {
		if (!strcmp(argv[1], "store_chunk"))
			test = STORE_CHUNK;
		else if (!strcmp(argv[1], "find_chunk")) {
			test = FIND_CHUNK;
			if (argc != 3)
				usage();
			digest = argv[2];
			if (!valid_digest(digest)) {
				fprintf(stderr, "Invalid digest\n");
				exit(-3);
			}
		}
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(9876);

	sk = socket(AF_INET, SOCK_STREAM, 0);
	if (sk < 0) {
		fprintf(stderr, "socket: %s\n", strerror(errno));
		exit(-1);
	}

	if (connect(sk, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
		fprintf(stderr, "connect: %s\n", strerror(errno));
		exit(-2);
	}

	if (!event_init()) {
		fprintf(stderr, "event_init: %s\n", strerror(errno));
		exit(-3);
	}

	bev = bufferevent_new(sk, bev_read, NULL, bev_error, NULL);
	if (!bev) {
		fprintf(stderr, "bufferevent_new: %s\n", strerror(errno));
		exit(-3);
	}

	bufferevent_enable(bev, EV_READ|EV_WRITE);

	buf = evbuffer_new();
	assert(buf != NULL);

	if (test == SELF_TEST) {
		for (i = 0; i < VALUE_SIZE; i ++)
			value[i] = random();

		printf("Storing value %s\n", sha1_string(value, VALUE_SIZE));

		evbuffer_add_printf(buf, "%s ", STORE_VALUE);
		base64_encode_evbuf(buf, value, VALUE_SIZE);
		evbuffer_add(buf, "\r\n", 2);

	} else if (test == FIND_CHUNK) {
		evbuffer_add_printf(buf, "%s %s\r\n", FIND_VALUE, digest);

	} else if (test == STORE_CHUNK) {
		int ch;
		memset(value, 0, VALUE_SIZE);
		for (i = 0; i < VALUE_SIZE && (ch = getchar()) != -1; i ++)
			value[i] = ch;

		printf("Storing value %s\n", sha1_string(value, VALUE_SIZE));

		evbuffer_add_printf(buf, "%s ", STORE_VALUE);
		base64_encode_evbuf(buf, value, VALUE_SIZE);
		evbuffer_add(buf, "\r\n", 2);
	}

	bufferevent_write_buffer(bev, buf);
	evbuffer_free(buf);
	fprintf(stderr, "*** event_dispatch: %d\n", event_dispatch());
	return 0;
}

