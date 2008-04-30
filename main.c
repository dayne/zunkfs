
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>

#include <event.h>

#include "base64.h"

struct client {
	int fd;
	struct bufferevent *bev;
	struct sockaddr_in addr;
};

struct node {
	struct sockaddr_in addr;
	unsigned char id[SHA_DIGEST_LENGTH];
	struct node *next;
};

#define node_addr(node)		((node)->addr.sin_addr)
#define node_addr_string(node)	inet_ntoa(node_addr(node))
#define node_port(node)		ntohs((node)->addr.sin_port)

#define FIND_VALUE		"find_chunk"
#define FIND_VALUE_LEN		(sizeof(FIND_VALUE) - 1)
#define STORE_VALUE		"store_chunk"
#define STORE_VALUE_LEN		(sizeof(STORE_VALUE) - 1)
#define REQUEST_DONE		"request_done"
#define REQUEST_DONE_LEN	(sizeof(REQUEST_DONE) - 1)
#define STORE_NODE		"store_node"
#define STORE_NODE_LEN		(sizeof(STORE_NODE) - 1)

static char *value_dir = NULL;
static const char hex_digits[] = "0123456789abcdef";

static struct node *node_head = NULL;
static struct node **node_tailp = &node_head;

static char *prog;
static struct sockaddr_in my_addr;

#define NODE_VEC_MAX	5

static int store_node(char *addr_str)
{
	struct sockaddr_in addr;
	struct node *node;
	char *port;

	port = strchr(addr_str, ':');
	if (!port)
		return -EINVAL;

	*port++ = 0;
	
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(port));

	if (!inet_aton(addr_str, &addr.sin_addr))
		return -EINVAL;

	for (node = node_head; node; node = node->next)
		if (!memcmp(&addr, &node->addr, sizeof(struct sockaddr_in)))
			return -EEXIST;

	node = malloc(sizeof(struct node));
	if (!node)
		return -ENOMEM;

	node->addr = addr;
	SHA1((void *)&node->addr, sizeof(struct sockaddr_in), node->id);

	node->next = NULL;
	*node_tailp = node;
	node_tailp = &node->next;

	printf("added node %s:%u\n", node_addr_string(node), node_port(node));

	return 0;
}

static int distance(const void *va, const void *vb)
{
	const unsigned *a = va;
	const unsigned *b = vb;
	int i;

	for (i = 0; i < 5; i ++) {
		unsigned bit = ffs(a[i] ^ b[i]);
		if (bit)
			return 160 - (bit + i * 32);
	}

	return -1;
}

static int nearest_nodes(const char *key_str, struct node **node_vec, int max)
{
	unsigned char key[SHA_DIGEST_LENGTH];
	const char *a, *b;
	int d, i, dist_vec[max], count = -1;
	struct node *node;

	if (strlen(key_str) < SHA_DIGEST_LENGTH*2)
		return 0;

	for (i = 0; i < SHA_DIGEST_LENGTH; i ++) {
		a = strchr(hex_digits, *key_str++);
		b = strchr(hex_digits, *key_str++);
		if (!a || !b)
			return 0;

		key[i] = (a - hex_digits) | ((b - hex_digits) << 4);
	}

	for (i = 0; i < max; i ++)
		node_vec[i] = NULL;

	for (node = node_head; node; node = node->next) {
		d = distance(key, node->id);
		for (i = 0; i < max; i ++) {
			if (!node_vec[i] || d < dist_vec[i]) {
				node_vec[i] = node;
				dist_vec[i] = d;
				if (count < i)
					count = i;
				break;
			}
		}
	}

	return count + 1;
}

static unsigned char *find_value(const char *key_str, size_t *size)
{
	unsigned char *value;
	struct stat st;
	char path[PATH_MAX];
	ssize_t n;
	int i, fd, len;

	fprintf(stderr, "find_value(%s)\n", key_str);

	if (strlen(key_str) != SHA_DIGEST_LENGTH * 2) {
		fprintf(stderr, "find_value: key invalid length\n");
		return NULL;
	}

	for (i = 0; key_str[i]; i ++) {
		if (!strchr(hex_digits, key_str[i])) {
			fprintf(stderr, "find_value: key not in hex format\n");
			return NULL;
		}
	}


	len = snprintf(path, PATH_MAX, "%s/%s", value_dir, key_str);
	if (len == PATH_MAX) {
		fprintf(stderr, "find_value: path too long.\n");
		return NULL;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "open(%s): %s\n", path, strerror(errno));
		return NULL;
	}

	if (fstat(fd, &st)) {
		fprintf(stderr, "stat(%s): %s\n", path, strerror(errno));
		close(fd);
		return NULL;
	}

	value = malloc(st.st_size);
	if (!value) {
		fprintf(stderr, "find_value: %s\n", strerror(errno));
		close(fd);
		return NULL;
	}

	fprintf(stderr, "chunk size: %zu\n", (size_t)st.st_size);

	n = read(fd, value, st.st_size);
	if (n < 0) 
		fprintf(stderr, "find_value: read error: %s\n", strerror(errno));

	close(fd);

	if (n < 0) {
		free(value);
		return NULL;
	}

	*size = n;
	return value;
}

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

static void store_value(const unsigned char *value, size_t size,
		const char *key_str)
{
	char path[PATH_MAX];
	int fd, len;

	len = snprintf(path, PATH_MAX, "%s/%s", value_dir, key_str);
	if (len == PATH_MAX) {
		fprintf(stderr, "store_value: path too long\n");
		return;
	}

	fd = open(path, O_WRONLY|O_EXCL|O_CREAT);
	if (fd < 0) {
		fprintf(stderr, "store_value(%s): %s\n", path, strerror(errno));
		return;
	}

	write(fd, value, size);
	close(fd);
}


static void kill_client(struct client *cl)
{
	close(cl->fd);
	bufferevent_free(cl->bev);
	free(cl);
}

static void cl_read_cb(struct bufferevent *bev, void *arg)
{
	struct client *cl = arg;
	struct evbuffer *input = bev->input;
	struct evbuffer *output;
	const char *end;
	const char *buf;
	char *msg;
	unsigned len;
	unsigned char *value;
	const char *key_str;
	size_t value_size;
	struct node *node_vec[NODE_VEC_MAX];
	int i, node_count;

	end = (const char *)evbuffer_find(input, (u_char *)"\r\n", 2);
	if (!end)
		return;

	buf = (const char *)EVBUFFER_DATA(input);
	len = end - buf;
	msg = alloca(len + 2);

	if (!msg)
		goto out;

	memcpy(msg, buf, len);
	msg[len] = 0;
	evbuffer_drain(input, len + 2);

	if (!strncmp(msg, FIND_VALUE, FIND_VALUE_LEN)) {
		msg += FIND_VALUE_LEN + 1;
		output = evbuffer_new();

		value = find_value(msg, &value_size);
		if (value) {
			evbuffer_add_printf(output, "%s ", STORE_VALUE);
			base64_encode_evbuf(output, value, value_size);
			free(value);
			evbuffer_add(output, "\r\n", 2);
		} else {
			node_count =
				nearest_nodes(msg, node_vec, NODE_VEC_MAX);
			if (node_count < 0)
				goto out;

			for (i = 0; i < node_count; i ++) {
				evbuffer_add_printf(output, "%s %s:%u\r\n",
						STORE_NODE,
						node_addr_string(node_vec[i]),
						node_port(node_vec[i]));
			}
		}

		evbuffer_add_printf(output, "%s %s\r\n", REQUEST_DONE, msg);
		bufferevent_write_buffer(bev, output);
		evbuffer_free(output);
		return;
		
	} else if (!strncmp(msg, STORE_VALUE, STORE_VALUE_LEN)) {
		msg += STORE_VALUE_LEN + 1;
		
		len = base64_size(len - STORE_VALUE_LEN - 1);

		value = alloca(len);
		if (!value)
			goto out;

		output = evbuffer_new();
		value_size = base64_decode(msg, value, len);
		key_str = sha1_string(value, value_size);
		store_value(value, value_size, key_str);

		node_count = nearest_nodes(msg, node_vec, NODE_VEC_MAX);
		if (node_count < 0)
			goto out;

		for (i = 0; i < node_count; i ++) {
			evbuffer_add_printf(output, "%s %s:%u\r\n",
					STORE_NODE,
					node_addr_string(node_vec[i]),
					node_port(node_vec[i]));
		}

		evbuffer_add_printf(output, "%s %s\r\n", REQUEST_DONE, key_str);
		bufferevent_write_buffer(bev, output);
		evbuffer_free(output);
		return;
	}

out:
	fprintf(stderr, "Killing client %p\n", cl);
	kill_client(cl);
}

static void cl_error_cb(struct bufferevent *bev, short what, void *arg)
{
	struct client *cl = arg;
	printf("client disconnected: %p\n", cl);
	close(cl->fd);
	bufferevent_free(cl->bev);
	free(cl);
}

static void accept_client(int fd, short event, void *arg)
{
	struct client *cl;
	socklen_t addr_len;

	cl = malloc(sizeof(struct client));
	if (!cl)
		return;

	addr_len = sizeof(struct sockaddr_in);

	cl->fd = accept(fd, (struct sockaddr *)&cl->addr, &addr_len);
	if (cl->fd == -1) {
		free(cl);
		return;
	}

	cl->bev = bufferevent_new(cl->fd, cl_read_cb, NULL, cl_error_cb, cl);
	if (!cl->bev) {
		close(cl->fd);
		free(cl);
		return;
	}

	bufferevent_enable(cl->bev, EV_READ);
	bufferevent_enable(cl->bev, EV_WRITE);

	printf("client connected: %p %s\n", cl, inet_ntoa(cl->addr.sin_addr));
}

enum {
	OPT_HELP,
	OPT_PEER,
	OPT_ADDR,
};

static struct option opts[] = {
	{ "help", no_argument, NULL, OPT_HELP },
	{ "peer", required_argument, NULL, OPT_PEER },
	{ "addr", required_argument, NULL, OPT_ADDR },
	{ NULL }
};

static void usage(int exit_code)
{
#define show_opt(opt...) fprintf(stderr, opt)
	show_opt("Usage: %s [ options ]\n", prog);
	show_opt("--help\n");
	show_opt("--peer <ip:port>    connect to this peer\n");
	show_opt("--addr <[ip:]port>  listen on specified IP and port.\n");
	exit(exit_code);
}

static int proc_opt(int opt, char *arg)
{
	char *port;
	int err;

	switch(opt) {
	case OPT_HELP:
		usage(0);
	case OPT_PEER:
		err = store_node(arg);
		if (err && err != -EEXIST) {
			fprintf(stderr, "Invalid peer.\n");
			return err;
		}
		return 0;
	case OPT_ADDR:
		port = strchr(arg, ':');
		if (!port) {
			fprintf(stderr, "No port in address %s.\n", arg);
			return -EINVAL;
		}
		*port++ = 0;

		my_addr.sin_port = htons(atoi(port));
		if (*arg && !inet_aton(arg, &my_addr.sin_addr)) {
			fprintf(stderr, "Invalid address %s.\n", arg);
			return -EINVAL;
		}

		return 0;
	default:
		return -1;
	}
}

int main(int argc, char **argv)
{
	struct event accept_event;
	int sk, reuse = 1, opt, err;
	char cwd[PATH_MAX];

	prog = basename(argv[0]);

	my_addr.sin_family = AF_INET;
	my_addr.sin_addr.s_addr = INADDR_ANY;
	my_addr.sin_port = htons(9876);

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		err = proc_opt(opt, optarg);
		if (err)
			usage(err);
	}

	if (optind != argc)
		usage(-1);

	getcwd(cwd, PATH_MAX);

	if (asprintf(&value_dir, "%s/.chunks", cwd) == -1) {
		fprintf(stderr, "%s\n", strerror(errno));
		exit(-1);
	}

	sk = socket(AF_INET, SOCK_STREAM, 0);
	if (sk < 0) {
		fprintf(stderr, "socket: %s\n", strerror(errno));
		exit(-1);
	}

	if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int))) {
		fprintf(stderr, "reuseaddr: %s\n", strerror(errno));
		exit(-1);
	}

	if (bind(sk, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_in))) {
		fprintf(stderr, "bind: %s\n", strerror(errno));
		exit(-1);
	}

	if (listen(sk, 1)) {
		fprintf(stderr, "listen: %s\n", strerror(errno));
		exit(-1);
	}

	if (!event_init()) {
		fprintf(stderr, "event_init: %s\n", strerror(errno));
		exit(-2);
	}

	event_set(&accept_event, sk, EV_READ|EV_PERSIST, accept_client, NULL);
	event_add(&accept_event, NULL);

	printf("Listening on %s:%u\n", inet_ntoa(my_addr.sin_addr),
			ntohs(my_addr.sin_port));

	event_dispatch();

	fprintf(stderr, "Event processing done.\n");
	return 0;
}

