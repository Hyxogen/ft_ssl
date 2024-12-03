#ifndef SSL_DIGEST_MD4
#define SSL_DIGEST_MD4

#include <ssl/types.h>

#define MD4_BLOCK_SIZE 64

struct md4_ctx {
	union {
		u8 bytes[MD4_BLOCK_SIZE];
		u32 words[MD4_BLOCK_SIZE / sizeof(u32)];
	} block;

	u32 state[4];
	u8 nwritten[8];
	size_t offset;
};

void md4_init(struct md4_ctx *ctx);
void md4_update(struct md4_ctx *ctx, const void *buf, size_t n);
void md4_final(struct md4_ctx *ctx, unsigned char *dest);
static const size_t md4_digest_len = 4 * sizeof(u32);

#endif
