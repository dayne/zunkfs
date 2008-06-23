
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
#include <evdns.h>

#include "base64.h"
#include "list.h"
#include "digest.h"
#include "utils.h"
#include "zunkfs.h"
#include "chunk-db.h"

struct node {
	int fd;
	struct bufferevent *bev;
	struct sockaddr_in addr;
	struct list_head nd_entry;
	struct event connect_event;
};

#define node_addr(node)		((node)->addr.sin_addr)
#define node_addr_string(node)	inet_ntoa(node_addr(node))
#define node_port(node)		ntohs((node)->addr.sin_port)

#define node_is_addr(node, addr) \
	(node_addr(node).s_addr == (addr)->sin_addr.s_addr && \
	 node_port(node) == ntohs((addr)->sin_port))

#define FIND_VALUE		"find_chunk"
#define FIND_VALUE_LEN		(sizeof(FIND_VALUE) - 1)
#define STORE_VALUE		"store_chunk"
#define STORE_VALUE_LEN		(sizeof(STORE_VALUE) - 1)
#define REQUEST_DONE		"request_done"
#define REQUEST_DONE_LEN	(sizeof(REQUEST_DONE) - 1)
#define STORE_NODE		"store_node"
#define STORE_NODE_LEN		(sizeof(STORE_NODE) - 1)

#define NODE_VEC_MAX	5

static LIST_HEAD(node_list);
static LIST_HEAD(client_list);

static char *prog;
static struct sockaddr_in my_addr;
static unsigned forward_stores = 0;
static unsigned nr_chunkdbs = 0;

static inline unsigned char *__data_digest(const void *buf, size_t len,
		unsigned char *digest)
{
	assert(digest != NULL);
	SHA1(buf, len, digest);
	return digest;
}

#define data_digest(buf, len) __data_digest(buf, len, alloca(SHA_DIGEST_LENGTH))

#define node_digest(node) data_digest(&(node)->addr, sizeof(struct sockaddr_in))

static struct sockaddr_in *__string_sockaddr_in(const char *str,
		struct sockaddr_in *sa)
{
	char *addr_str;
	char *port;

	assert(sa != NULL);
	assert(str != NULL);

	memset(sa, 0, sizeof(struct sockaddr_in));

	addr_str = alloca(strlen(str) + 1);
	if (!addr_str)
		return NULL;

	strcpy(addr_str, str);

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

static void free_node(struct node *node)
{
	event_del(&node->connect_event);
	list_del(&node->nd_entry);
	close(node->fd);
	bufferevent_free(node->bev);
	free(node);
}

static int trim_nodes(void)
{
	struct list_head *list;

	if (!list_empty(&client_list))
		list = &client_list;
	else if (!list_empty(&node_list))
		list = &node_list;
	else
		return 0;

	free_node(list_entry(list->prev, struct node, nd_entry));
	return 1;
}

static void connectcb(int fd, short event, void *arg)
{
	struct node *node = arg;
	int err;

	if (!connect(fd, (struct sockaddr *)&node->addr,
				sizeof(struct sockaddr_in)) ||
			errno == EISCONN) {
		TRACE("Connected to peer %s:%u\n", 
				inet_ntoa(node->addr.sin_addr),
				ntohs(node->addr.sin_port));
		bufferevent_enable(node->bev, EV_READ | EV_WRITE);
		return;
	}

	if (errno == EALREADY || errno == EINPROGRESS) {
		event_add(&node->connect_event, NULL);
		return;
	}

	err = errno;
	TRACE("Failed to connect to %s:%u: %s\n", 
			inet_ntoa(node->addr.sin_addr),
			ntohs(node->addr.sin_port),
			strerror(err));

	free_node(node);
}

static void readcb(struct bufferevent *bev, void *arg);
static void errorcb(struct bufferevent *bev, short what, void *arg);

static int setup_node(struct node *node)
{
	int fl;

	event_set(&node->connect_event, node->fd, EV_WRITE, connectcb, node);

	node->bev = bufferevent_new(node->fd, readcb, NULL, errorcb, node);
	if (!node->bev) {
		close(node->fd);
		free(node);
		return -ENOMEM;
	}

	fl = fcntl(node->fd, F_GETFL);
	fcntl(node->fd, F_SETFL, fl | O_NONBLOCK);

	return 0;
}

static void nearest_nodes(const unsigned char *, struct evbuffer *, int);

static int connect_node(struct node *node)
{
	struct evbuffer *evbuf;

	evbuf = evbuffer_new();
	if (!evbuf) {
		ERROR("eek: failed to allocate evbuffer\n");
		free_node(node);
		return -ENOMEM;
	}

	bufferevent_disable(node->bev, EV_READ | EV_WRITE);

	evbuffer_add_printf(evbuf, "%s :%u\r\n", STORE_NODE,
			ntohs(my_addr.sin_port));

	nearest_nodes(node_digest(node), evbuf, NODE_VEC_MAX);

	bufferevent_write_buffer(node->bev, evbuf);
	evbuffer_free(evbuf);

	connectcb(node->fd, EV_WRITE, node);
	return 0;
}

static int store_node(const struct sockaddr_in *addr)
{
	struct node *node;
	int err;

	list_for_each_entry(node, &node_list, nd_entry)
		if (node_is_addr(node, addr))
			return -EEXIST;

	node = malloc(sizeof(struct node));
	if (!node)
		return -ENOMEM;

again:
	node->fd = socket(AF_INET, SOCK_STREAM, 0);
	if (node->fd == -1) {
		err = -errno;
		if ((errno == ENFILE || errno == EMFILE) && trim_nodes())
			goto again;
		return err;
	}

	err = setup_node(node);
	if (err)
		return err;

	node->addr = *addr;

	list_add_tail(&node->nd_entry, &node_list);

	TRACE("added node %s:%u\n", node_addr_string(node), node_port(node));

	return connect_node(node);
}

static void dns_resolvecb(int result, char type, int count, int ttl, 
		void *addresses, void *arg)
{
	struct in_addr *addrs = addresses;
	struct sockaddr_in sa;
	char *addr_str = arg;
	char *port;

	assert(addr_str != NULL);

	port = addr_str + strlen(addr_str) + 1;

	if(result != DNS_ERR_NONE || type != DNS_IPv4_A) {
		ERROR("Failed to resolve %s.\n", addr_str);
		free(addr_str);
		return;
	}

	TRACE("Resolved %s to be %s\n", addr_str, inet_ntoa(*addrs));

	sa.sin_family = AF_INET;
	sa.sin_addr = *addrs;
	sa.sin_port = htons(atoi(port));

	store_node(&sa);
	free(addr_str);
}

static int dns_resolve(char *addr_str) 
{
	struct sockaddr_in *addr;
	char *addr_str_copy;
	char *port;

	addr = string_sockaddr_in(addr_str);
	if (addr)
		return store_node(addr);

	addr_str_copy = strdup(addr_str);
	if (!addr_str_copy)
		return -ENOMEM;
       
	port = strchr(addr_str_copy, ':');
	if(!port)
		return -EINVAL;
	*port++ = 0;

	TRACE("Resolving %s... \n", addr_str_copy);

	if(evdns_resolve_ipv4(addr_str_copy, 0, dns_resolvecb, addr_str_copy)) {
		ERROR("Failed to resolve %s.\n", addr_str_copy);
		return -EINVAL;
	}

	return 0;
}

static inline int node_distance(const struct node *node,
		const unsigned char *key)
{
	return digest_distance(key, node_digest(node));
}

static int __nearest_nodes(const unsigned char *key, struct node **node_vec,
		int *dist_vec, int max)
{
	int d, i, count = -1;
	struct node *node;

	for (i = 0; i < max; i ++)
		node_vec[i] = NULL;

	list_for_each_entry(node, &node_list, nd_entry) {
		d = node_distance(node, key);
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

static void nearest_nodes(const unsigned char *key, struct evbuffer *output,
		int max)
{
	struct node *node_vec[max];
	int dist_vec[max];
	int i, count;

	count = __nearest_nodes(key, node_vec, dist_vec, max);
	TRACE("%d nodes near %s\n", count, digest_string(key));
	for (i = 0; i < count; i ++) {
		evbuffer_add_printf(output, "%s %s:%u\r\n",
				STORE_NODE,
				node_addr_string(node_vec[i]),
				node_port(node_vec[i]));
		TRACE("\t%s:%u\n",
				node_addr_string(node_vec[i]),
				node_port(node_vec[i]));
	}
}

static int find_value(const unsigned char *key, struct evbuffer *output)
{
	unsigned char value[CHUNK_SIZE];
	int len;

	len = read_chunk(value, key);

	if (len == CHUNK_SIZE) {
		evbuffer_add_printf(output, "%s ", STORE_VALUE);
		base64_encode_evbuf(output, value, CHUNK_SIZE);
		evbuffer_add(output, "\r\n", 2);
		return 1;
	}

	return 0;
}

static int store_value(const char *value, unsigned char *digest)
{
	unsigned char chunk[CHUNK_SIZE];

	if (base64_decode(value, chunk, CHUNK_SIZE) != CHUNK_SIZE)
		return -EINVAL;

	return write_chunk(chunk, digest);
}

static void forward_value(const unsigned char *key, const char *encoded_value,
		struct node *from_node)
{
	struct node *node_vec[NODE_VEC_MAX];
	int dist_vec[NODE_VEC_MAX];
	struct evbuffer *buf;
	int i, count, d;

	buf = evbuffer_new();
	if (!buf)
		return;

	d = node_distance(from_node, key);

	count = __nearest_nodes(key, node_vec, dist_vec, NODE_VEC_MAX);
	for (i = 0; i < count; i ++) {
		if (d < dist_vec[i])
			continue;
		evbuffer_add_printf(buf, "%s %s\r\n", STORE_VALUE,
				encoded_value);
		bufferevent_write_buffer(node_vec[i]->bev, buf);
	}

	evbuffer_free(buf);
}


static inline void request_done(const char *key_str, struct evbuffer *output)
{
	evbuffer_add_printf(output, "%s %s\r\n", REQUEST_DONE, key_str);
}

static void proc_msg(const char *buf, size_t len, struct node *node)
{
	unsigned char digest[SHA_DIGEST_LENGTH];
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

		__string_digest(msg, digest);

		if (!find_value(digest, output))
			nearest_nodes(digest, output, NODE_VEC_MAX);

		request_done(msg, output);
		
	} else if (!strncmp(msg, STORE_VALUE, STORE_VALUE_LEN)) {
		msg += STORE_VALUE_LEN + 1;
		len -= STORE_VALUE_LEN - 1;
		
		if (store_value(msg, digest) != CHUNK_SIZE) {
			free_node(node);
			return;
		}

		if (forward_stores)
			forward_value(digest, msg, node);
		else
			nearest_nodes(digest, output, NODE_VEC_MAX);

		request_done(digest_string(digest), output);

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
		end = (const char *)evbuffer_find(bev->input,
				(u_char *)"\r\n", 2);
		if (!end)
			return;

		proc_msg(buf, end - buf, arg);
		evbuffer_drain(bev->input, (end - buf) + 2);
	}
}

static void errorcb(struct bufferevent *bev, short what, void *arg)
{
	struct node *cl = arg;
	TRACE("client disconnected: %p\n", cl);
	free_node(cl);
}

static void accept_client(int fd, short event, void *arg)
{
	struct node *cl;
	socklen_t addr_len;
	int err;

	cl = malloc(sizeof(struct node));
	if (!cl)
		return;

	addr_len = sizeof(struct sockaddr_in);

again:
	cl->fd = accept(fd, (struct sockaddr *)&cl->addr, &addr_len);
	if (cl->fd == -1) {
		if (errno == EAGAIN)
			goto again;
		if ((errno == ENFILE || errno == EMFILE) && trim_nodes())
			goto again;

		free(cl);
		return;
	}

	err = setup_node(cl);
	if (err)
		return;

	list_add(&cl->nd_entry, &client_list);

	bufferevent_enable(cl->bev, EV_READ | EV_WRITE);

	TRACE("client connected: %p %s\n", cl, inet_ntoa(cl->addr.sin_addr));
}

enum {
	OPT_HELP = 'h',
	OPT_PEER = 'p',
	OPT_ADDR = 'a',
	OPT_FORWORD_STORES = 'f',
	OPT_LOG = 'l',
	OPT_CHUNK_DB = 'c',
};

static const char short_opts[] = {
	OPT_HELP,
	OPT_PEER,
	OPT_ADDR,
	OPT_FORWORD_STORES,
	OPT_LOG,
	OPT_CHUNK_DB,
	0
};

static const struct option long_opts[] = {
	{ "help", no_argument, NULL, OPT_HELP },
	{ "peer", required_argument, NULL, OPT_PEER },
	{ "addr", required_argument, NULL, OPT_ADDR },
	{ "forward-store", no_argument, NULL, OPT_FORWORD_STORES },
	{ "chunk-db", required_argument, NULL, OPT_CHUNK_DB },
	{ NULL }
};

#define USAGE \
"-h|--help\n"\
"-p|--peer <(ip|hostname):port>    Connect to this peer.\n"\
"-a|--addr <[ip:]port>             Listen on specified IP and port.\n"\
"-f|--forward-store                Automatically forward store requests,\n"\
"                                  and don't send nearest nodes as a reply.\n"\
"-l|--log [level,]<file>           Enable logging of (E)rrors, (W)arnings,\n"\
"                                  (T)races to a file. File can be a path,\n"\
"                                  stdout, or stderr.\n"\
"-c|--chunk-db <spec>              Add a chunk-db.\n"\
"\nChunk-db specs:\n"

static void usage(int exit_code)
{
	fprintf(stderr, "Usage: %s [ options ]\n", prog);
	fprintf(stderr, "%s\n", USAGE);
	help_chunkdb();
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
		err = dns_resolve(arg);
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

	case OPT_FORWORD_STORES:
		forward_stores = 1;
		return 0;

	case OPT_LOG:
		err = set_logging(optarg);
		if (err) {
			fprintf(stderr, "Failed to enable logging: %s\n",
					strerror(-err));
			return err;
		}
		return 0;

	case OPT_CHUNK_DB:
		err = add_chunkdb(optarg);
		if (err) {
			fprintf(stderr, "Failed to add chunk-db %s: %s\n",
					optarg, strerror(-err));
			return err;
		}
		nr_chunkdbs ++;
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

	if (!event_init()) {
		fprintf(stderr, "event_init: %s\n", strerror(errno));
		exit(-2);
	}

	if (evdns_init()) {
		fprintf(stderr, "evdns_init: %s\n", strerror(errno));
		exit(-2);
	}

	while ((opt = getopt_long(argc, argv, short_opts, long_opts, NULL))
			!= -1) {
		err = proc_opt(opt, optarg);
		if (err)
			usage(err);
	}

	if (optind != argc)
		usage(-1);

	if (!nr_chunkdbs) {
		fprintf(stderr, "Must specify at least one chunk database.\n\n");
		usage(-1);
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


	event_set(&accept_event, sk, EV_READ|EV_PERSIST, accept_client, NULL);
	event_add(&accept_event, NULL);

	TRACE("Listening on %s:%u\n", inet_ntoa(my_addr.sin_addr),
			ntohs(my_addr.sin_port));

	event_dispatch();

	fprintf(stderr, "Event processing done.\n");
	return 0;
}

