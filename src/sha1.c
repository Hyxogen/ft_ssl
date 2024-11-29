#include <ssl/digest/sha1.h>
#include <ssl/mp.h>
#include <ssl/math.h>
#include <ft/string.h>
#include <common/endian.h>
#include <ssl/digest/common.h>
#include <limits.h>

void sha1_init(struct sha1_ctx *ctx)
{
	ctx->offset = 0;
	mp_init(ctx->nwritten, sizeof(ctx->nwritten));

	ctx->hash.a = 0x67452301;
	ctx->hash.b = 0xefcdab89;
	ctx->hash.c = 0x98badcfe;
	ctx->hash.d = 0x10325476;
	ctx->hash.e = 0xc3d2e1f0;
}

static void sha1_generate_w(u32 dest[SHA1_ROUNDS], const u8 block[SHA1_BLOCK_LEN])
{
	ft_memcpy(dest, block, SHA1_BLOCK_LEN);

	for (unsigned t = 0; t < 16; t++) {
		dest[t] = from_be32(dest[t]);
	}

	for (unsigned t = 16; t < SHA1_ROUNDS; t++) {
		dest[t] = ssl_rotleft32(dest[t - 3] ^ dest[t - 8] ^ dest[t - 14] ^ dest[t - 16], 1);
	}
}

static u32 sha1_f1(u32 x, u32 y, u32 z)
{
	return (x & y) | ((~x) & z);
}

static u32 sha1_f2(u32 x, u32 y, u32 z)
{
	return x ^ y ^ z;
}

static u32 sha1_f3(u32 x, u32 y, u32 z)
{
	return (x & y) | (x & z) | (y & z);
}

static u32 sha1_f4(u32 x, u32 y, u32 z)
{
	return sha1_f2(x, y, z);
}

static void sha1_transform(union sha1_hash *hash, const u8 block[SHA1_BLOCK_LEN])
{
	union sha1_hash prev = *hash;

	u32 w[SHA1_ROUNDS];
	sha1_generate_w(w, block);

	for (unsigned t = 0; t < SHA1_ROUNDS; t++) {
		u32 f;
		u32 k;

		if (t < 20) {
			f = sha1_f1(prev.b, prev.c, prev.d);
			k = 0x5a827999;
		} else if (t < 40) {
			f = sha1_f2(prev.b, prev.c, prev.d);
			k = 0x6ed9eba1;
		} else if (t < 60) {
			f = sha1_f3(prev.b, prev.c, prev.d);
			k = 0x8f1bbcdc;
		} else {
			f = sha1_f4(prev.b, prev.c, prev.d);
			k = 0xca62c1d6;
		}

		u32 temp = ssl_rotleft32(prev.a, 5) + f + prev.e + w[t] + k;

		prev.e = prev.d;
		prev.d = prev.c;
		prev.c = ssl_rotleft32(prev.b, 30);
		prev.b = prev.a;
		prev.a = temp;
	}

	for (unsigned i = 0; i < SHA1_HASH_NUM_WORDS; i++) {
		hash->words[i] += prev.words[i];
	}
}

static void sha1_transform_wrapper(void *p)
{
	struct sha1_ctx *ctx = p;
	sha1_transform(&ctx->hash, ctx->block);
}

void sha1_update(struct sha1_ctx *ctx, const void *buf, size_t n)
{
	dgst_generic_update(ctx->block, SHA1_BLOCK_LEN, &ctx->offset, buf, n, sha1_transform_wrapper, ctx);
	/* TODO check if n * CHAR_BIT wraps around? */
	mp_add(ctx->nwritten, sizeof(ctx->nwritten), n * CHAR_BIT);
}

static void sha1_do_pad(struct sha1_ctx *ctx)
{
	dgst_generic_pad(ctx->block, SHA1_BLOCK_LEN, ctx->nwritten,
			 sizeof(ctx->nwritten), ctx->offset, ENDIAN_BIG,
			 sha1_transform_wrapper, ctx);
}

static void sha1_create_hash(unsigned char dest[SHA1_DIGEST_LEN], const union sha1_hash *hash)
{
	u32 *dest32 = (void*) dest;

	for (unsigned i = 0; i < SHA1_HASH_NUM_WORDS; i++) {
		*dest32++ = to_be32(hash->words[i]);
	}
}

void sha1_final(struct sha1_ctx *ctx, unsigned char dest[SHA1_DIGEST_LEN])
{
	sha1_do_pad(ctx);
	sha1_create_hash(dest, &ctx->hash);
}
