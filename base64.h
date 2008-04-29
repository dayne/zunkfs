
#ifndef __BASE64_H__
#define __BASE64_H__

/*
 * This is not-quite-MIME-spec compliant, as I don't
 * insert a \r\n for every 76th character.
 */

static inline size_t base64_size(size_t len)
{
	return (len * 3 + 3) / 4;
}

static inline size_t base64_length(size_t size)
{
	return (size * 4 + 2) / 3;
}

struct evbuffer;

size_t base64_decode(const char *str, unsigned char *buf, size_t size);
int base64_encode_evbuf(struct evbuffer *evbuf, const unsigned char *s,
		size_t length);

#endif

