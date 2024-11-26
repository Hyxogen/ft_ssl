#ifndef SSL_DIGEST_SHA1_H
#define SSL_DIGEST_SHA1_H

#include <ssl/types.h>
#include <stddef.h>

#define SHA1_BLOCK_LEN 64
#define SHA1_ROUNDS 80
#define SHA1_HASH_NUM_WORDS 5
#define SHA1_DIGEST_LEN (SHA1_HASH_NUM_WORDS * sizeof(u32))

union sha1_hash {
	u32 words[5];
	struct {
		u32 a;
		u32 b;
		u32 c;
		u32 d;
		u32 e;
	} __attribute__((packed));
};

struct sha1_ctx {
	u8 block[SHA1_BLOCK_LEN];

	size_t offset;
	u8 nwritten[8];
	union sha1_hash hash;
};

void sha1_init(struct sha1_ctx *ctx);
void sha1_update(struct sha1_ctx *ctx, const void *buf, size_t n);
void sha1_final(struct sha1_ctx *ctx, unsigned char dest[SHA1_DIGEST_LEN]);
static const size_t sha1_digest_len = SHA1_DIGEST_LEN;

#endif
