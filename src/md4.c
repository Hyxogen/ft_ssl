#include <ssl/digest/md4.h>
#include <ft/string.h>
#include <common/endian.h>
#include <common/bitops.h>
#include <assert.h>

static_assert(CHAR_BIT % 8 == 0, "weird bits per byte");

#define MD4_A 0
#define MD4_B 1
#define MD4_C 2
#define MD4_D 3

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

void md4_init(struct md4_ctx *ctx)
{
	ctx->state[MD4_A] = 0x67452301;
	ctx->state[MD4_B] = 0xefcdab89;
	ctx->state[MD4_C] = 0x98badcfe;
	ctx->state[MD4_D] = 0x10325476;

	ctx->offset = 0;
	ctx->nwritten = 0;
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

static void md4_transform(u32 state[static 4],
			  const unsigned char block[static MD4_BLOCK_LEN])
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

		f = state[MD4_A] + f + from_le32(&block[MD4_K[i] * 4]);

		state[MD4_A] = state[MD4_D];
		state[MD4_D] = state[MD4_C];
		state[MD4_C] = state[MD4_B];
		state[MD4_B] = rotleft32(f, MD4_ROTTABLE[i]);
	}

	for (unsigned i = 0; i < 4; i++) {
		state[i] += saved[i];
	}
}

void md4_update(struct md4_ctx *ctx, const void *buf, size_t n)
{
	const unsigned char *cbuf = buf;

	for (size_t i = 0; i < n; i++) {
		ctx->block[ctx->offset++] = cbuf[i];

		if (ctx->offset >= MD4_BLOCK_LEN) {
			md4_transform(ctx->state, ctx->block);
			ctx->offset = 0;
		}
	}

	ctx->nwritten += n * CHAR_BIT;
}

static const u8 md4_padding[128] = {0x80};

static void md4_do_pad(struct md4_ctx *ctx)
{
	size_t padding = 1; /* 1 for the 0x80 byte */

	size_t offset = ctx->offset;
	offset = (offset + 1) % MD4_BLOCK_LEN;

	size_t stop = MD4_BLOCK_LEN - sizeof(ctx->nwritten);
	if (offset > stop) {
		padding += MD4_BLOCK_LEN - offset;
		padding += stop;
	} else {
		padding += stop - offset;
	}

	unsigned char length[8];
	to_le64(length, ctx->nwritten);

	md4_update(ctx, md4_padding, padding);
	md4_update(ctx, length, sizeof(length));
}

static void md4_create_hash(unsigned char dest[MD4_DIGEST_LEN],
			    const u32 state[static 4])
{
	for (size_t i = 0; i < 4; i++) {
		to_le32(&dest[i * sizeof(u32)], state[i]);
	}
}

void md4_final(unsigned char dest[MD4_DIGEST_LEN], struct md4_ctx *ctx)
{
	md4_do_pad(ctx);
	md4_create_hash(dest, ctx->state);
}
