#ifndef SSL_MD5_H
#define SSL_MD5_H

#include <stddef.h>
#include <ssl/types.h>
#include <limits.h>

#define MD5_BLOCK_LEN (512/CHAR_BIT)
#define MD5_DIGEST_LEN (128/CHAR_BIT)

struct md5_ctx {
	unsigned char block[MD5_BLOCK_LEN];

	u32 state[4];
	size_t offset;
	u64 nwritten;
};

void md5_init(struct md5_ctx *ctx);
void md5_update(struct md5_ctx *ctx, const void *buf, size_t n);
void md5_final(unsigned char dest[MD5_DIGEST_LEN], struct md5_ctx *ctx);
static const size_t md5_digest_len = MD5_DIGEST_LEN;

#endif
