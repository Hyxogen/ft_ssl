#include <ssl/digest/md4.h>
#include <ssl/digest/common.h>
#include <ssl/math.h>
#include <ssl/mp.h>
#include <ft/string.h>
#include <limits.h>
#include <assert.h>

static_assert(CHAR_BIT == 8, "this code expects 8 bit bytes");

#define MD4_A 0
#define MD4_B 1
#define MD4_C 2
#define MD4_D 3

void md4_init(struct md4_ctx *ctx)
{
	ctx->state[MD4_A] = 0x67452301;
	ctx->state[MD4_B] = 0xefcdab89;
	ctx->state[MD4_C] = 0x98badcfe;
	ctx->state[MD4_D] = 0x10325476;

	ctx->offset = 0;
	mp_init(ctx->nwritten, sizeof(ctx->nwritten));
}

static u32 md4_f(u32 x, u32 y, u32 z)
{
	return (x & y) | ((~x) & z);
}

static u32 md4_g(u32 x, u32 y, u32 z)
{
	return (x & y) | (x & z) | (y & z);
}

static u32 md4_h(u32 x, u32 y, u32 z)
{
	return x ^ y ^ z;
}

static const u8 MD4_K[48] = {
    0, 1, 2, 3,	 4, 5,	6, 7,  8, 9, 10, 11, 12, 13, 14, 15, /* round 1 */
    0, 4, 8, 12, 1, 5,	9, 13, 2, 6, 10, 14, 3,	 7,  11, 15, /* round 2 */
    0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5,	 13, 3,	 11, 7,	 15, /* round 3 */
};

static const u8 MD4_ROTTABLE[48] = {
    3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, /* round 1 */
    3, 5, 9,  13, 3, 5, 9,  13, 3, 5, 9,  13, 3, 5, 9,	13, /* round 2 */
    3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, /* round 3 */
};

static void md4_transform(u32 state[4], const u32 block[MD4_BLOCK_SIZE/4])
{
	u32 saved[4];

	ft_memcpy(saved, state, sizeof(saved));

	for (unsigned i = 0; i < 48; i++) {
		u32 f;

		if (i < 16) {
			f = md4_f(state[MD4_B], state[MD4_C], state[MD4_D]);
		} else if (i < 32) {
			f = md4_g(state[MD4_B], state[MD4_C], state[MD4_D]) + 0x5A827999;
		} else {
			f = md4_h(state[MD4_B], state[MD4_C], state[MD4_D]) + 0x6ED9EBA1;
		}

		f = state[MD4_A] + f + from_le32(block[MD4_K[i]]);

		state[MD4_A] = state[MD4_D];
		state[MD4_D] = state[MD4_C];
		state[MD4_C] = state[MD4_B];
		state[MD4_B] = ssl_rotleft32(f, MD4_ROTTABLE[i]);
	}

	for (unsigned i = 0; i < 4; i++) {
		state[i] += saved[i];
	}
}

static void md4_transform_wrapper(void *p)
{
	struct md4_ctx *ctx = p;
	md4_transform(ctx->state, ctx->block.words);
}

void md4_update(struct md4_ctx *ctx, const void *buf, size_t n)
{
	dgst_generic_update(ctx->block.bytes, MD4_BLOCK_SIZE, &ctx->offset,
			    buf, n, md4_transform_wrapper, ctx);
	mp_add(ctx->nwritten, sizeof(ctx->nwritten), n * CHAR_BIT);
}

static void md4_pad(struct md4_ctx *ctx)
{
	dgst_generic_pad(ctx->block.bytes, MD4_BLOCK_SIZE, ctx->nwritten,
			 sizeof(ctx->nwritten), ctx->offset, ENDIAN_LITTLE,
			 md4_transform_wrapper, ctx);
}

static void md4_create_hash(unsigned char *dest, struct md4_ctx *ctx)
{
	for (unsigned i = 0; i < 4; i++) {
		u32 tmp = to_le32(ctx->state[i]);
		dest = ft_mempcpy(dest, &tmp, sizeof(tmp));
	}
}

void md4_final(struct md4_ctx *ctx, unsigned char *dest)
{
	md4_pad(ctx);
	md4_create_hash(dest, ctx);
}
