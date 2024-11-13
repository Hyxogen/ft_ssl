#ifndef SSL_SHA2_H
#define SSL_SHA2_H

#include <ssl/types.h>
#include <stddef.h>

#define SHA256_BLOCK_LEN 64
#define SHA256_ROUNDS 64
#define SHA256_HASH_NWORDS 8

#define SHA512_BLOCK_LEN 128
#define SHA512_ROUNDS 80

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

	u64 nwritten;
	union sha256_hash hash;
};

void sha256_init(struct sha256_ctx *ctx);
void sha256_free(struct sha256_ctx *ctx);
size_t sha256_update(struct sha256_ctx *ctx, const void *buf, size_t n);
void sha256_final(struct sha256_ctx *ctx, unsigned char *dest);
static const size_t sha256_digest_len = SHA256_HASH_NWORDS * sizeof(u32);

union sha512_hash {
	u64 words[8];
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

	u64 nwritten[2];
	union sha512_hash hash;
};

void sha512_init(struct sha512_ctx *ctx);
void sha512_free(struct sha512_ctx *ctx);
size_t sha512_update(struct sha512_ctx *ctx, const void *buf, size_t n);
void sha512_final(struct sha512_ctx *ctx, unsigned char *dest);
static const size_t sha512_digest_len = 8 * sizeof(u64);

#endif
