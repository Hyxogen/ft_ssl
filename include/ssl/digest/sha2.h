#ifndef SSL_SHA2_H
#define SSL_SHA2_H

#include <ssl/types.h>
#include <stddef.h>
#include <limits.h>

#define SHA256_BLOCK_LEN (512/CHAR_BIT)
#define SHA256_ROUNDS 64
#define SHA256_DIGEST_LEN (256/CHAR_BIT)

#define SHA224_DIGEST_LEN (224/CHAR_BIT)

#define SHA512_BLOCK_LEN (1024/CHAR_BIT)
#define SHA512_ROUNDS 80
#define SHA512_DIGEST_LEN (512/CHAR_BIT)

#define SHA384_HASH_NUM_WORDS 6
#define SHA384_DIGEST_NBYTES (SHA384_HASH_NUM_WORDS * sizeof(u64))

struct sha256_ctx {
	u8 block[SHA256_BLOCK_LEN];
	u32 state[8];

	size_t offset;
	u64 nwritten;
};

void sha256_init(struct sha256_ctx *ctx);
void sha256_update(struct sha256_ctx *ctx, const void *buf, size_t n);
void sha256_final(unsigned char dest[SHA256_DIGEST_LEN], struct sha256_ctx *ctx);
static const size_t sha256_digest_len = SHA256_DIGEST_LEN;

struct sha224_ctx {
	struct sha256_ctx inner;
};

void sha224_init(struct sha224_ctx *ctx);
void sha224_update(struct sha224_ctx *ctx, const void *buf, size_t n);
void sha224_final(unsigned char dest[SHA224_DIGEST_LEN], struct sha224_ctx *ctx);
static const size_t sha224_digest_len = SHA224_DIGEST_LEN;

struct sha512_ctx {
	unsigned char block[SHA512_BLOCK_LEN];

	u64 state[8];
	size_t offset;
	u8 nwritten[16];
};

void sha512_init(struct sha512_ctx *ctx);
void sha512_update(struct sha512_ctx *ctx, const void *buf, size_t n);
void sha512_final(unsigned char dest[SHA512_DIGEST_LEN], struct sha512_ctx *ctx);
static const size_t sha512_digest_len = SHA512_DIGEST_LEN;

struct sha384_ctx {
	struct sha512_ctx inner;
};

void sha384_init(struct sha384_ctx *ctx);
void sha384_update(struct sha384_ctx *ctx, const void *buf, size_t n);
void sha384_final(struct sha384_ctx *ctx, unsigned char *dest);
static const size_t sha384_digest_len = SHA384_DIGEST_NBYTES;

#endif
