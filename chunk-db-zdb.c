/*
 * ZunkDB back-end.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>

#include <event.h>

#include "zunkfs.h"
#include "chunk-db.h"
#include "utils.h"
#include "mutex.h"
#include "base64.h"

struct zdb_info {
	struct sockaddr_in start_node;
	struct timeval timeout;
};

struct node;

struct request {
	struct evbuffer *evbuf;
	struct event_base *base;
	unsigned char *chunk;
	const unsigned char *digest;
	struct node *node_list;
	struct sockaddr_in *addr_list;
	unsigned addr_count;
	unsigned done;
};

struct node {
	struct event connect_event;
	struct bufferevent *bev;
	struct sockaddr_in addr;
	int sk;
	struct request *request;
	struct node *next, **pprev;
};

#define CACHE_MAX	100

static struct node *node_cache = NULL;
static unsigned cache_count = 0;
static DECLARE_MUTEX(cache_mutex);

static void node_add(struct node *node, struct node **list)
{
	node->pprev = list;
	node->next = *list;
	if (node->next)
		node->next->pprev = &node->next;
	*list = node;
}

static void node_del(struct node *node)
{
	if ((*node->pprev = node->next))
		node->next->pprev = node->pprev;
}

static struct node *find_node(const struct sockaddr_in *sa)
{
	struct node *node;

	lock(&cache_mutex);
	for (node = node_cache; node; node = node->next) {
		if (sa->sin_addr.s_addr == node->addr.sin_addr.s_addr &&
				sa->sin_port == node->addr.sin_port) {
			cache_count --;
			node_del(node);
			break;
		}
	}
	unlock(&cache_mutex);

	return node;
}

static void free_node(struct node *node)
{
	node_del(node);
	bufferevent_free(node->bev);
	close(node->sk);
	free(node);
}

static void __cache_node(struct node *node)
{
	node->request = NULL;

	node_del(node);
	node_add(node, &node_cache);

	bufferevent_disable(node->bev, EV_READ|EV_WRITE);

	if (++cache_count > CACHE_MAX) {
		for (node = node_cache; node->next; node = node->next)
			;
		free_node(node);
	}
}

static void cache_node(struct node *node)
{
	lock(&cache_mutex);
	__cache_node(node);
	unlock(&cache_mutex);
}

static int send_request_to(struct request *request,
		const struct sockaddr_in *addr);

static void store_node(struct request *request, char *addr_str)
{
	char *port;
	struct sockaddr_in addr;
	struct sockaddr_in *uaddr;
	int i;

	port = strchr(addr_str, ':');
	if (!port)
		return;

	*port++ = 0;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(port));

	if (!inet_aton(addr_str, &addr.sin_addr))
		return;

	for (i = 0; i < request->addr_count; i ++) {
		uaddr = &request->addr_list[i];
		if (!memcmp(&addr, uaddr, sizeof(struct sockaddr_in)))
			return;
	}

	uaddr = realloc(request->addr_list,
			sizeof(struct sockaddr_in) * (i + 1));
	if (!uaddr)
		return;

	uaddr[i] = addr;
	request->addr_list = uaddr;
	request->addr_count ++;

	send_request_to(request, &addr);
}

#define FIND_CHUNK		"find_chunk"
#define FIND_CHUNK_LEN		(sizeof(FIND_CHUNK) - 1)
#define STORE_CHUNK		"store_chunk"
#define STORE_CHUNK_LEN		(sizeof(STORE_CHUNK) - 1)
#define REQUEST_DONE		"request_done"
#define REQUEST_DONE_LEN	(sizeof(REQUEST_DONE) - 1)
#define STORE_NODE		"store_node"
#define STORE_NODE_LEN		(sizeof(STORE_NODE) - 1)

static int proc_msg(const char *buf, size_t len, struct node *node)
{
	struct request *req = node->request;
	char *msg = alloca(len + 1);

	assert(msg != NULL);

	memcpy(msg, buf, len);
	msg[len] = 0;

	if (!strncmp(msg, STORE_CHUNK, STORE_CHUNK_LEN)) {
		msg += STORE_CHUNK_LEN + 1;
		if (req->chunk) {
			base64_decode(msg, req->chunk, CHUNK_SIZE);
			req->chunk = NULL;
		}

	} else if (!strncmp(msg, REQUEST_DONE, REQUEST_DONE_LEN)) {
		msg += REQUEST_DONE_LEN + 1;
		if (!strcmp(msg, digest_string(req->digest))) {
			req->done ++;
			cache_node(node);
			return 1;
		}

	} else if (!strncmp(msg, STORE_NODE, STORE_NODE_LEN)) {
		msg += STORE_NODE_LEN + 1;
		store_node(req, msg);
	}

	return 0;
}

static void readcb(struct bufferevent *bev, void *arg)
{
	struct node *node = arg;
	const char *buf;
	const char *end;
	int drain_all = 0;

	for (;;) {
		buf = (const char *)EVBUFFER_DATA(bev->input);
		end = (const char *)evbuffer_find(bev->input,
				(u_char *)"\r\n", 2);
		if (!end)
			return;

		if (!drain_all)
			drain_all = proc_msg(buf, end - buf, node);
		evbuffer_drain(bev->input, end - buf + 2);
	}
}

static void errorcb(struct bufferevent *bev, short what, void *arg)
{
	struct node *node = arg;
	TRACE("node=%p\n", node);
	free_node(node);
}

static void try_connect(int fd, short what, void *arg)
{
	struct node *node = arg;
	
	TRACE("node=%p\n", node);
again:
	if (!connect(fd, (struct sockaddr *)&node->addr,
				sizeof(struct sockaddr_in)) ||
			errno == EISCONN) {
		TRACE("connected!\n");
		bufferevent_enable(node->bev, EV_READ|EV_WRITE);
		return;
	}

	if (errno == EINTR)
		goto again;

	if (errno == EALREADY || errno == EINPROGRESS)
		event_add(&node->connect_event, NULL);
	else {
		free_node(node);
		TRACE("connect failed\n");
	}
}

static void write_request(struct node *node, struct request *request)
{
	node->request = request;
	node_add(node, &request->node_list);

	bufferevent_base_set(request->base, node->bev);
	bufferevent_write(node->bev, EVBUFFER_DATA(request->evbuf),
			EVBUFFER_LENGTH(request->evbuf));
}

static int send_request_to(struct request *request,
		const struct sockaddr_in *addr)
{
	struct node *node;

	node = find_node(addr);
	if (node) {
		write_request(node, request);
		bufferevent_enable(node->bev, EV_READ|EV_WRITE);
		return 0;
	}

	node = malloc(sizeof(struct node));
	if (!node)
		return -ENOMEM;

	node->addr = *addr;

	node->sk = socket(AF_INET, SOCK_STREAM, 0);
	if (node->sk < 0) {
		ERROR("socket: %s\n", strerror(errno));
		free(node);
		return -EIO;
	}

	node->bev = bufferevent_new(node->sk, readcb, NULL, errorcb, node);
	if (!node->bev) {
		ERROR("bufferevent_new: %s\n", strerror(errno));
		close(node->sk);
		free(node);
		return -EIO;
	}

	bufferevent_disable(node->bev, EV_READ | EV_WRITE);

	write_request(node, request);

	event_set(&node->connect_event, node->sk, EV_WRITE, try_connect, node);
	event_base_set(request->base, &node->connect_event);

	try_connect(node->sk, EV_WRITE, node);

	return 0;
}

static void timeout_cb(int fd, short event, void *arg) { }

static int send_request(struct evbuffer *evbuf, struct zdb_info *db_info,
		const unsigned char *digest, unsigned char *chunk)
{
	struct timeval timeout = db_info->timeout;
	struct request request;
	struct event to_event;
	int err;

	request.evbuf = evbuf;
	request.chunk = chunk;
	request.digest = digest;
	request.node_list = NULL;
	request.addr_list = NULL;
	request.addr_count = 0;
	request.done = 0;

	request.base = event_base_new();
	if (!request.base) {
		ERROR("event_base: %s\n", strerror(errno));
		return -EIO;
	}

	err = send_request_to(&request, &db_info->start_node);
	if (err) {
		event_base_free(request.base);
		return err;
	}

	timeout_set(&to_event, timeout_cb, NULL);
	event_base_set(request.base, &to_event);
	timeout_add(&to_event, &timeout);

	err = -EIO;
	for (;;) {
		if (!timeout_pending(&to_event, &timeout))
			break;
		if (!request.node_list)
			break;
		if (event_base_loop(request.base, EVLOOP_ONCE))
			break;
		if (!request.done)
			continue;
		if (!chunk)
			err = CHUNK_SIZE;
		else if (!request.chunk && verify_chunk(chunk, digest)) {
			err = CHUNK_SIZE;
			break;
		} else {
			request.chunk = chunk;
			request.done --;
		}
	}

	timeout_del(&to_event);

	lock(&cache_mutex);
	while (request.node_list)
		__cache_node(request.node_list);
	unlock(&cache_mutex);

	free(request.addr_list);

	evbuffer_free(request.evbuf);
	event_base_free(request.base);

	return err;
}

static int zdb_read_chunk(unsigned char *chunk, const unsigned char *digest,
		void *db_info)
{
	struct evbuffer *request;

	TRACE("digest=%s\n", digest_string(digest));

	request = evbuffer_new();
	if (!request)
		return -ENOMEM;

	if (evbuffer_add_printf(request, "%s %s\r\n", FIND_CHUNK,
				digest_string(digest)) < 0) {
		TRACE("evbuffer_add failed\n");
		evbuffer_free(request);
		return -EIO;
	}

	return send_request(request, db_info, digest, chunk);
}

static int zdb_write_chunk(const unsigned char *chunk,
		const unsigned char *digest, void *db_info)
{
	struct evbuffer *request;

	TRACE("digest=%s\n", digest_string(digest));

	request = evbuffer_new();
	if (!request)
		return -ENOMEM;

	if (evbuffer_add_printf(request, "%s ", STORE_CHUNK) < 0 ||
			base64_encode_evbuf(request, chunk, CHUNK_SIZE) < 0 ||
			evbuffer_add(request, "\r\n", 2) < 0) {
		TRACE("evbuffer_add failed\n");
		evbuffer_free(request);
		return -EIO;
	}

	return send_request(request, db_info, digest, NULL);
}

static struct chunk_db *zdb_chunkdb_ctor(int mode, const char *spec)
{
	struct chunk_db *cdb;
	struct zdb_info *zdb_info;
	char *port;
	char *addr;
	char *timeout;

	if (strncmp(spec, "zunkdb:", 7))
		return NULL;

	spec += 7;
	addr = alloca(strlen(spec) + 1);
	if (!addr)
		return ERR_PTR(ENOMEM);

	strcpy(addr, spec);

	port = strchr(addr, ':');
	if (!port) {
		fprintf(stderr, "Spec missing node port #.\n");
		return ERR_PTR(EINVAL);
	}

	*port++ = 0;

	/*
	 * FIXME: should try to parse options
	 */
	timeout = strchr(port, ',');
	if (timeout)
		*timeout++ = 0;

	cdb = malloc(sizeof(struct chunk_db) + sizeof(struct zdb_info));
	if (!cdb)
		return ERR_PTR(ENOMEM);

	zdb_info = cdb->db_info = (void *)(cdb + 1);

	if (!inet_aton(addr, &zdb_info->start_node.sin_addr)) {
		fprintf(stderr, "Invalid node address: %s\n", addr);
		free(cdb);
		return ERR_PTR(EINVAL);
	}

	/*
	 * default timeout is 60 seconds
	 */
	zdb_info->timeout.tv_sec = 60;
	zdb_info->timeout.tv_usec = 0;

	if (timeout)
		zdb_info->timeout.tv_sec = atoi(timeout);

	zdb_info->start_node.sin_port = ntohs(atoi(port));
	zdb_info->start_node.sin_family = AF_INET;

	cdb->read_chunk = zdb_read_chunk;
	cdb->write_chunk = (mode == CHUNKDB_RW) ? zdb_write_chunk : NULL;

	return cdb;
}

static void __attribute__((constructor)) init_chunkdb_zdb(void)
{
	register_chunkdb(zdb_chunkdb_ctor);
}

