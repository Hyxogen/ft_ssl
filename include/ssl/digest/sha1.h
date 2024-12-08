#ifndef SSL_DIGEST_SHA1_H
#define SSL_DIGEST_SHA1_H

#include <ssl/types.h>
#include <limits.h>

#define SHA1_BLOCK_LEN (512/CHAR_BIT)
#define SHA1_DIGEST_LEN (160/CHAR_BIT)

struct sha1_ctx {
	unsigned char block[SHA1_BLOCK_LEN];

	size_t offset;
	u64 nwritten;

	u32 state[5];
};

void sha1_init(struct sha1_ctx *ctx);
void sha1_update(struct sha1_ctx *ctx, const void *buf, size_t n);
void sha1_final(unsigned char dest[SHA1_DIGEST_LEN], struct sha1_ctx *ctx);
static const size_t sha1_digest_len = SHA1_DIGEST_LEN;

#endif
