#ifndef SSL_SHA2_H
#define SSL_SHA2_H

#include <ssl/types.h>
#include <stddef.h>

#define SHA256_BLOCK_LEN 64

union sha256_state {
	u32 words[8];
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
	union {
		u32 words[SHA256_BLOCK_LEN / sizeof(u32)];
		u8 bytes[SHA256_BLOCK_LEN];
	} block;

	size_t nwritten;
	union sha256_state state;
};

int sha256_init(struct sha256_ctx *ctx);
void sha256_free(struct sha256_ctx *ctx);
size_t sha256_update(struct sha256_ctx *ctx, const void *buf, size_t n);
size_t sha256_final(struct sha256_ctx *ctx, unsigned char *dest);
static const size_t sha256_digest_len = 8 * sizeof(u32);

#endif
