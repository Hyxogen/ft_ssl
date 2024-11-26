#ifndef SSL_SHA2_H
#define SSL_SHA2_H

#include <ssl/types.h>
#include <stddef.h>

#define SHA256_BLOCK_LEN 64
#define SHA256_ROUNDS 64
#define SHA256_HASH_NUM_WORDS 8
#define SHA256_DIGEST_LEN (SHA256_HASH_NUM_WORDS * sizeof(u32))

#define SHA224_HASH_NUM_WORDS 7
#define SHA224_DIGEST_LEN (SHA224_HASH_NUM_WORDS * sizeof(u32))

#define SHA512_BLOCK_LEN 128
#define SHA512_ROUNDS 80
#define SHA512_HASH_NUM_WORDS 8
#define SHA512_DIGEST_LEN (SHA512_HASH_NUM_WORDS * sizeof(u64))

#define SHA384_HASH_NUM_WORDS 6
#define SHA384_DIGEST_LEN (SHA384_HASH_NUM_WORDS * sizeof(u64))

union sha256_hash {
	u32 words[SHA256_HASH_NUM_WORDS];
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

	size_t offset;
	u8 nwritten[8];
	union sha256_hash hash;
};

void sha256_init(struct sha256_ctx *ctx);
size_t sha256_update(struct sha256_ctx *ctx, const void *buf, size_t n);
void sha256_final(struct sha256_ctx *ctx, unsigned char *dest);
static const size_t sha256_digest_len = SHA256_DIGEST_LEN;

struct sha224_ctx {
	struct sha256_ctx inner;
};

void sha224_init(struct sha224_ctx *ctx);
size_t sha224_update(struct sha224_ctx *ctx, const void *buf, size_t n);
void sha224_final(struct sha224_ctx *ctx, unsigned char *dest);
static const size_t sha224_digest_len = SHA224_DIGEST_LEN;

union sha512_hash {
	u64 words[SHA512_HASH_NUM_WORDS];
	struct {
		u64 a;
		u64 b;
		u64 c;
		u64 d;
		u64 e;
		u64 f;
		u64 g;
		u64 h;
	} __attribute__((packed));
} __attribute__((packed));

struct sha512_ctx {
	u8 block[SHA512_BLOCK_LEN];

	size_t offset;
	u8 nwritten[16];
	union sha512_hash hash;
};

void sha512_init(struct sha512_ctx *ctx);
size_t sha512_update(struct sha512_ctx *ctx, const void *buf, size_t n);
void sha512_final(struct sha512_ctx *ctx, unsigned char *dest);
static const size_t sha512_digest_len = SHA512_DIGEST_LEN;

struct sha384_ctx {
	struct sha512_ctx inner;
};

void sha384_init(struct sha384_ctx *ctx);
size_t sha384_update(struct sha384_ctx *ctx, const void *buf, size_t n);
void sha384_final(struct sha384_ctx *ctx, unsigned char *dest);
static const size_t sha384_digest_len = SHA384_DIGEST_LEN;

#endif
