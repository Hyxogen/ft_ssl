#ifndef SSL_DIGEST_MD4
#define SSL_DIGEST_MD4

#include <ssl/types.h>
#include <limits.h>

#define MD4_BLOCK_LEN (512/CHAR_BIT)
#define MD4_DIGEST_LEN (128/CHAR_BIT)

struct md4_ctx {
	unsigned char block[MD4_BLOCK_LEN];

	u32 state[4];
	size_t offset;
	u64 nwritten;
};

void md4_init(struct md4_ctx *ctx);
void md4_update(struct md4_ctx *ctx, const void *buf, size_t n);
void md4_final(unsigned char dest[MD4_DIGEST_LEN], struct md4_ctx *ctx);
static const size_t md4_digest_len = MD4_DIGEST_LEN;

#endif
