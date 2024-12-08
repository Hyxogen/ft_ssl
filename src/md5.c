#include <common/bitops.h>
#include <common/endian.h>
#include <ft/string.h>
#include <limits.h>
#include <ssl/digest/md5.h>
#include <assert.h>

static_assert(CHAR_BIT % 8 == 0, "weird bits per byte");

#define MD5_A 0
#define MD5_B 1
#define MD5_C 2
#define MD5_D 3

/*
	import math

	print("static const u32 MD5_K[64] = {")
	c=2**32
	for i in range(0, 64):
		print("0x{:08x},".format(math.floor(c * abs(math.sin(i + 1)))))

	print("};");
*/
static const u32 MD5_K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static const u8 MD5_ROTTABLE[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, /* round 1 */
    5, 9,  14, 20, 5, 9,  14, 20, 5, 9,	 14, 20, 5, 9,	14, 20, /* round 2 */
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, /* round 3 */
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, /* round 4 */
};

void md5_init(struct md5_ctx *ctx)
{
	ctx->state[MD5_A] = 0x67452301;
	ctx->state[MD5_B] = 0xefcdab89;
	ctx->state[MD5_C] = 0x98badcfe;
	ctx->state[MD5_D] = 0x10325476;

	ctx->offset = 0;
	ctx->nwritten = 0;
}

static u32 md5_f(u32 x, u32 y, u32 z)
{
	return (x & y) | ((~x) & z);
}

static u32 md5_g(u32 x, u32 y, u32 z)
{
	return (x & z) | (y & (~z));
}

static u32 md5_h(u32 x, u32 y, u32 z)
{
	return x ^ y ^ z;
}

static u32 md5_i(u32 x, u32 y, u32 z)
{
	return y ^ (x | (~z));
}

static void md5_transform(u32 state[static 4],
			  const unsigned char block[static 64])
{
	u32 saved[4];
	ft_memcpy(saved, state, sizeof(saved));

	for (unsigned i = 0; i < 64; i++) {
		u32 f, g;

		if (i < 16) {
			f = md5_f(state[MD5_B], state[MD5_C], state[MD5_D]);
			g = i;
		} else if (i < 32) {
			f = md5_g(state[MD5_B], state[MD5_C], state[MD5_D]);
			g = ((i * 5) + 1) % 16;
		} else if (i < 48) {
			f = md5_h(state[MD5_B], state[MD5_C], state[MD5_D]);
			g = ((i * 3) + 5) % 16;
		} else {
			f = md5_i(state[MD5_B], state[MD5_C], state[MD5_D]);
			g = (i * 7) % 16;
		}

		f = f + state[MD5_A] + MD5_K[i] + from_le32(&block[g * sizeof(u32)]);

		state[MD5_A] = state[MD5_D];
		state[MD5_D] = state[MD5_C];
		state[MD5_C] = state[MD5_B];
		state[MD5_B] = state[MD5_B] + rotleft32(f, MD5_ROTTABLE[i]);
	}

	for (unsigned i = 0; i < 4; i++) {
		state[i] += saved[i];
	}
}

void md5_update(struct md5_ctx *ctx, const void *buf, size_t n)
{
	const unsigned char *cbuf = buf;

	for (size_t i = 0; i < n; i++) {
		ctx->block[ctx->offset++] = cbuf[i];

		if (ctx->offset >= MD5_BLOCK_LEN) {
			md5_transform(ctx->state, ctx->block);
			ctx->offset = 0;
		}
	}

	ctx->nwritten += n * CHAR_BIT;
}

static const u8 md5_padding[128] = {0x80};

static void md5_do_pad(struct md5_ctx *ctx)
{
	size_t padding = 1; /* 1 for the 0x80 byte */

	size_t offset = ctx->offset;
	offset = (offset + 1) % MD5_BLOCK_LEN;

	size_t stop = MD5_BLOCK_LEN - sizeof(ctx->nwritten);
	if (offset > stop) {
		padding += MD5_BLOCK_LEN - offset;
		padding += stop;
	} else {
		padding += stop - offset;
	}

	unsigned char length[8];
	to_le64(length, ctx->nwritten);

	md5_update(ctx, md5_padding, padding);
	md5_update(ctx, length, sizeof(length));
}

static void md5_create_hash(unsigned char dest[MD5_DIGEST_LEN],
			    const u32 state[static 4])
{
	for (size_t i = 0; i < 4; i++) {
		to_le32(&dest[i * sizeof(u32)], state[i]);
	}
}

void md5_final(unsigned char dest[MD5_DIGEST_LEN], struct md5_ctx *ctx)
{
	md5_do_pad(ctx);
	md5_create_hash(dest, ctx->state);
}
