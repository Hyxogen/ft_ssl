#ifndef SSL_SHA256_H
#define SSL_SHA256_H

#include <stddef.h>
#include <ssl/types.h>

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
		u32 words[16];
		u8 bytes[64];
	} chunk;

	size_t nwritten;
	union sha256_state state;
};

int sha256_init(struct sha256_ctx *ctx);
void sha256_free(struct sha256_ctx *ctx);
size_t sha256_write(struct sha256_ctx *ctx, const void *buf, size_t n);
size_t sha256_finalize(struct sha256_ctx *ctx, unsigned char *dest);

#endif
