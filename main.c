
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
#include "list.h"

struct node {
	int fd;
	struct bufferevent *bev;
	struct sockaddr_in addr;
	struct list_head nd_entry;
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

static LIST_HEAD(node_list);
static LIST_HEAD(client_list);

static char *prog;
static struct sockaddr_in my_addr;

static inline void *__node_digest(const struct node *node, unsigned char *digest)
{
	assert(digest != NULL);
	SHA1((void *)&node->addr, sizeof(struct sockaddr_in), digest);
	return digest;
}

#define node_digest(node) __node_digest(node, alloca(SHA_DIGEST_LENGTH))

static struct sockaddr_in *__string_sockaddr_in(const char *str, struct sockaddr_in *sa)
{
	char *addr_str;
	char *port;

	if (!sa || !str)
		return NULL;

	addr_str = alloca(strlen(str) + 1);
	if (!addr_str)
		return NULL;

	port = strchr(addr_str, ':');
	if (!port)
		return NULL;

	*port++ = 0;
	
	sa->sin_family = AF_INET;
	sa->sin_port = htons(atoi(port));
	sa->sin_addr.s_addr = INADDR_ANY;

	if (*addr_str && !inet_aton(addr_str, &sa->sin_addr))
		return NULL;

	return sa;
}

#define string_sockaddr_in(addr_str) \
	__string_sockaddr_in(addr_str, alloca(sizeof(struct sockaddr_in)))

#define NODE_VEC_MAX	5

static int store_node(const struct sockaddr_in *addr)
{
	struct node *node;

	list_for_each_entry(node, &node_list, nd_entry)
		if (!memcmp(addr, &node->addr, sizeof(struct sockaddr_in)))
			return -EEXIST;

	node = malloc(sizeof(struct node));
	if (!node)
		return -ENOMEM;

	node->addr = *addr;
	list_add_tail(&node->nd_entry, &node_list);

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

static int __nearest_nodes(const char *key_str, struct node **node_vec, int max)
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

	list_for_each_entry(node, &node_list, nd_entry) {
		d = distance(key, node_digest(node));
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

static void nearest_nodes(const char *key_str, struct evbuffer *output, int max)
{
	struct node *node_vec[max];
	int i, count;

	count = __nearest_nodes(key_str, node_vec, max);
	for (i = 0; i < count; i ++) {
		evbuffer_add_printf(output, "%s %s:%u\r\n",
				STORE_NODE,
				node_addr_string(node_vec[i]),
				node_port(node_vec[i]));
	}
}

static int find_value(const char *key_str, struct evbuffer *output)
{
	unsigned char *value;
	char path[PATH_MAX];
	struct stat st;
	ssize_t n;
	int i, fd, len;

	fprintf(stderr, "find_value(%s)\n", key_str);

	if (strlen(key_str) != SHA_DIGEST_LENGTH * 2) {
		fprintf(stderr, "find_value: key invalid length\n");
		return 0;
	}

	for (i = 0; key_str[i]; i ++) {
		if (!strchr(hex_digits, key_str[i])) {
			fprintf(stderr, "find_value: key not in hex format\n");
			return 0;
		}
	}


	len = snprintf(path, PATH_MAX, "%s/%s", value_dir, key_str);
	if (len == PATH_MAX) {
		fprintf(stderr, "find_value: path too long.\n");
		return 0;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "open(%s): %s\n", path, strerror(errno));
		return 0;
	}

	if (fstat(fd, &st)) {
		fprintf(stderr, "stat(%s): %s\n", path, strerror(errno));
		close(fd);
		return 0;
	}

	value = alloca(st.st_size);
	if (!value) {
		fprintf(stderr, "find_value: %s\n", strerror(errno));
		close(fd);
		return 0;
	}

	fprintf(stderr, "chunk size: %zu\n", (size_t)st.st_size);

	n = read(fd, value, st.st_size);
	if (n < 0) {
		fprintf(stderr, "find_value read error: %s\n", strerror(errno));
		close(fd);
		return 0;
	}
	
	evbuffer_add_printf(output, "%s ", STORE_VALUE);
	base64_encode_evbuf(output, value, st.st_size);
	evbuffer_add(output, "\r\n", 2);

	close(fd);

	return 1;
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

static void free_node(struct node *node)
{
	list_del(&node->nd_entry);
	close(node->fd);
	bufferevent_free(node->bev);
	free(node);
}

static inline void request_done(const char *key_str, struct evbuffer *output)
{
	evbuffer_add_printf(output, "%s %s\r\n", REQUEST_DONE, key_str);
}

static void proc_msg(const char *buf, size_t len, struct node *node)
{
	struct evbuffer *output;
	char *msg;

	output = evbuffer_new();
	if (!output)
		return;

	msg = alloca(len + 1);
	assert(msg != NULL);
	memcpy(msg, buf, len);
	msg[len] = 0;

	if (!strncmp(msg, FIND_VALUE, FIND_VALUE_LEN)) {
		msg += FIND_VALUE_LEN + 1;
		len -= FIND_VALUE_LEN + 1;

		if (!find_value(msg, output))
			nearest_nodes(msg, output, NODE_VEC_MAX);

		request_done(msg, output);
		
	} else if (!strncmp(msg, STORE_VALUE, STORE_VALUE_LEN)) {
		unsigned char *value;
		const char *key_str;

		msg += STORE_VALUE_LEN + 1;
		len -= STORE_VALUE_LEN - 1;
		
		len = base64_size(len);

		value = alloca(len);
		if (!value)
			return;

		len = base64_decode(msg, value, len);
		key_str = sha1_string(value, len);

		store_value(value, len, key_str);

		nearest_nodes(msg, output, NODE_VEC_MAX);

		request_done(key_str, output);

	} else if (!strncmp(msg, STORE_NODE, STORE_NODE_LEN)) {
		struct sockaddr_in *addr;

		msg += STORE_NODE_LEN + 1;
		len -= STORE_NODE_LEN - 1;

		addr = string_sockaddr_in(msg);
		if (!addr)
			return;

		if (addr->sin_addr.s_addr == INADDR_ANY)
			addr->sin_addr = node->addr.sin_addr;

		store_node(addr);
	}

	bufferevent_write_buffer(node->bev, output);
	evbuffer_free(output);
}

static void readcb(struct bufferevent *bev, void *arg)
{
	const char *buf, *end;

	for (;;) {
		buf = (const char *)EVBUFFER_DATA(bev->input);
		end = (const char *)evbuffer_find(bev->input, (u_char *)"\r\n", 2);
		if (!end)
			return;

		proc_msg(buf, end - buf, arg);
		evbuffer_drain(bev->input, (end - buf) + 2);
	}
}

static void errorcb(struct bufferevent *bev, short what, void *arg)
{
	struct node *cl = arg;
	printf("client disconnected: %p\n", cl);
	free_node(cl);
}

static int trim_clients(void)
{
	struct node *cl;

	if (list_empty(&client_list))
		return 0;

	cl = list_entry(client_list.prev, struct node, nd_entry);
	free_node(cl);
	return 1;
}

static void accept_client(int fd, short event, void *arg)
{
	struct node *cl;
	socklen_t addr_len;

	cl = malloc(sizeof(struct node));
	if (!cl)
		return;

	addr_len = sizeof(struct sockaddr_in);

again:
	cl->fd = accept(fd, (struct sockaddr *)&cl->addr, &addr_len);
	if (cl->fd == -1) {
		if (errno == EAGAIN)
			goto again;
		if ((errno == ENFILE || errno == EMFILE) && trim_clients())
			goto again;

		free(cl);
		return;
	}

	cl->bev = bufferevent_new(cl->fd, readcb, NULL, errorcb, cl);
	if (!cl->bev) {
		close(cl->fd);
		free(cl);
		return;
	}

	list_add(&cl->nd_entry, &client_list);

	bufferevent_enable(cl->bev, EV_READ | EV_WRITE);

	printf("client connected: %p %s\n", cl, inet_ntoa(cl->addr.sin_addr));
}

enum {
	OPT_HELP,
	OPT_PEER,
	OPT_ADDR,
	OPT_PATH,
};

static struct option opts[] = {
	{ "help", no_argument, NULL, OPT_HELP },
	{ "peer", required_argument, NULL, OPT_PEER },
	{ "addr", required_argument, NULL, OPT_ADDR },
	{ "chunk-dir", required_argument, NULL, OPT_PATH },
	{ NULL }
};

static void usage(int exit_code)
{
#define show_opt(opt...) fprintf(stderr, opt)
	show_opt("Usage: %s [ options ]\n", prog);
	show_opt("--help\n");
	show_opt("--peer <ip:port>    connect to this peer\n");
	show_opt("--addr <[ip:]port>  listen on specified IP and port\n");
	show_opt("--chunk-dir <path>  path to chunk directory\n");
	exit(exit_code);
}

static int proc_opt(int opt, char *arg)
{
	struct sockaddr_in *sa;
	int err;

	switch(opt) {
	case OPT_HELP:
		usage(0);
	case OPT_PEER:
		sa = string_sockaddr_in(arg);
		if (!sa) {
			fprintf(stderr, "Invalid peer address: %s\n", arg);
			return -EINVAL;
		}

		err = store_node(sa);
		if (err && err != -EEXIST) {
			fprintf(stderr, "store peer: %s.\n", strerror(-err));
			return err;
		}
		return 0;

	case OPT_ADDR:
		sa = string_sockaddr_in(arg);
		if (!sa) {
			fprintf(stderr, "Invalid address: %s\n", arg);
			return -EINVAL;
		}

		my_addr = *sa;
		return 0;

	case OPT_PATH:
		if (arg[0] != '/') {
			fprintf(stderr, "Must supply full path to "
					"chunks dir.\n");
			return -EINVAL;
		}

		if (access(arg, R_OK|W_OK|X_OK)) {
			int err = -errno;
			fprintf(stderr, "%s: %s\n", arg, strerror(-err));
			return err;
		}

		value_dir = arg;
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

	getcwd(cwd, PATH_MAX);

	if (strlen(cwd) >= PATH_MAX - sizeof("/.chunks")) {
		fprintf(stderr, "cwd: %s\n", strerror(ENAMETOOLONG));
		exit(-1);
	}

	strcat(cwd, "/.chunks");

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		err = proc_opt(opt, optarg);
		if (err)
			usage(err);
	}

	if (optind != argc)
		usage(-1);

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


