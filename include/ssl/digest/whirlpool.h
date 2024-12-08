#ifndef SSL_WHIRLPOOL_H
#define SSL_WHIRLPOOL_H

#include <ssl/types.h>
#include <limits.h>

#define WHIRLPOOL_BLOCK_LEN (512/CHAR_BIT)
#define WHIRLPOOL_DIGEST_LEN (512/CHAR_BIT)

struct whirlpool_ctx {
	unsigned char block[WHIRLPOOL_BLOCK_LEN];
	u8 state[512/8];

	size_t offset;
	u8 nwritten[32];
};

void whirlpool_init(struct whirlpool_ctx *ctx);
void whirlpool_update(struct whirlpool_ctx *ctx, const void *buf, size_t n);
void whirlpool_final(unsigned char dest[WHIRLPOOL_DIGEST_LEN], struct whirlpool_ctx *ctx);
static const size_t whirlpool_digest_len = WHIRLPOOL_DIGEST_LEN;

#endif
