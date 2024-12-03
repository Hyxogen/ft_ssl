#ifndef SSL_DIGEST_SHA3_H
#define SSL_DIGEST_SHA3_H

#include <ssl/types.h>

#define SHA3_224_DIGEST_NBYTES 28
#define SHA3_256_DIGEST_NBYTES 32
#define SHA3_512_DIGEST_NBYTES 64

struct sha3_ctx {
	union {
		u8 bytes[5*5*8];
		u64 words[5][5];
	} state;

	size_t offset; /* TODO use this */
	size_t bitrate;
};

void sha3_init(struct sha3_ctx *ctx, unsigned mdlen);
void sha3_update(struct sha3_ctx *ctx, const u8 *buf, size_t len);
void sha3_final(struct sha3_ctx *ctx, unsigned char *dest, size_t mdlen);

struct sha3_224_ctx {
	struct sha3_ctx inner;
};

static inline void sha3_224_init(struct sha3_224_ctx *ctx)
{
	sha3_init(&ctx->inner, SHA3_224_DIGEST_NBYTES);
}

static inline void sha3_224_update(struct sha3_224_ctx *ctx, const void *buf, size_t len)
{
	sha3_update(&ctx->inner, buf, len);
}

static inline void sha3_224_final(struct sha3_224_ctx *ctx, unsigned char *dest)
{
	sha3_final(&ctx->inner, dest, SHA3_224_DIGEST_NBYTES);
}

static const size_t sha3_224_digest_len = SHA3_224_DIGEST_NBYTES;

struct sha3_256_ctx {
	struct sha3_ctx inner;
};

static inline void sha3_256_init(struct sha3_256_ctx *ctx)
{
	sha3_init(&ctx->inner, SHA3_256_DIGEST_NBYTES);
}

static inline void sha3_256_update(struct sha3_256_ctx *ctx, const void *buf, size_t len)
{
	sha3_update(&ctx->inner, buf, len);
}

static inline void sha3_256_final(struct sha3_256_ctx *ctx, unsigned char *dest)
{
	sha3_final(&ctx->inner, dest, SHA3_256_DIGEST_NBYTES);
}

static const size_t sha3_256_digest_len = SHA3_256_DIGEST_NBYTES;

struct sha3_512_ctx {
	struct sha3_ctx inner;
};

static inline void sha3_512_init(struct sha3_512_ctx *ctx)
{
	sha3_init(&ctx->inner, SHA3_512_DIGEST_NBYTES);
}

static inline void sha3_512_update(struct sha3_512_ctx *ctx, const void *buf, size_t len)
{
	sha3_update(&ctx->inner, buf, len);
}

static inline void sha3_512_final(struct sha3_512_ctx *ctx, unsigned char *dest)
{
	sha3_final(&ctx->inner, dest, SHA3_512_DIGEST_NBYTES);
}

static const size_t sha3_512_digest_len = SHA3_512_DIGEST_NBYTES;

#endif