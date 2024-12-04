#ifndef SSL_MD5_H
#define SSL_MD5_H

#include <stddef.h>
#include <ssl/types.h>

struct md5_ctx {
	union {
		u32 words[16];
		u8 bytes[64];
	} chunk;

	u32 state[4];
	u8 nwritten[8];
	size_t offset;
};

void md5_init(struct md5_ctx *ctx);
void md5_update(struct md5_ctx *ctx, const void *buf, size_t n);
void md5_final(struct md5_ctx *ctx, unsigned char *dest);
static const size_t md5_digest_len = 4 * sizeof(u32);

#endif
