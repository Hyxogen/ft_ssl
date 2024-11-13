#ifndef SSL_SHA2_H
#define SSL_SHA2_H

#include <ssl/types.h>
#include <stddef.h>

#define SHA256_BLOCK_LEN 64
#define SHA256_ROUNDS 64
#define SHA256_HASH_NWORDS 8

union sha256_hash {
	u32 words[SHA256_HASH_NWORDS];
	struct {
		u32 a;
		u32 b;
		u32 c;
		u32 d;
		u32 e;
		u32 f;
		u32 g;
		u32 h;
	};
} __attribute__((packed));

struct sha256_ctx {
	u8 block[SHA256_BLOCK_LEN];

	size_t nwritten;
	union sha256_hash hash;
};

int sha256_init(struct sha256_ctx *ctx);
void sha256_free(struct sha256_ctx *ctx);
size_t sha256_update(struct sha256_ctx *ctx, const void *buf, size_t n);
size_t sha256_final(struct sha256_ctx *ctx, unsigned char *dest);
static const size_t sha256_digest_len = SHA256_HASH_NWORDS * sizeof(u32);

#endif
