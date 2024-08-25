#ifndef SSL_MD5_H
#define SSL_MD5_H

#include <stddef.h>
#include <ssl/types.h>

#define MD5_A 0
#define MD5_B 1
#define MD5_C 2
#define MD5_D 3

struct md5_ctx {
	union {
		u32 words[16];
		u8 bytes[64];
	} chunk;

	u32 state[4];
	u64 nwritten;
};

int md5_init(struct md5_ctx *ctx);
void md5_free(struct md5_ctx *ctx);

size_t md5_write(struct md5_ctx *ctx, const void *buf, size_t n);
size_t md5_finalize(struct md5_ctx *ctx, unsigned char *dest);

#endif
