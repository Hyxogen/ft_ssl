#ifndef SSL_WHIRLPOOL_H
#define SSL_WHIRLPOOL_H

#include <ssl/types.h>
#include <stddef.h>
#include <limits.h>
#include <assert.h>

static_assert(CHAR_BIT == 8, "this code expects 8 bit bytes");

/* TODO make naming consistent, is named BLOCK_LEN in sha2 */
#define W_BLOCK_SIZE 64

struct whirlpool_ctx {
	u8 block[W_BLOCK_SIZE];

	u8 hash[W_BLOCK_SIZE];
	u64 nwritten[4];
};

void whirlpool_init(struct whirlpool_ctx *ctx);
void whirlpool_free(struct whirlpool_ctx *ctx);
size_t whirlpool_update(struct whirlpool_ctx *ctx, const void *buf, size_t n);
void whirlpool_final(struct whirlpool_ctx *ctx, unsigned char *dest);
static const size_t whirlpool_digest_len = W_BLOCK_SIZE;

#endif
