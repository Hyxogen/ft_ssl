#include <assert.h>
#include <ft/string.h>
#include <ssl/math.h>
#include <ssl/digest/md5.h>
#include <common/endian.h>
#include <ssl/digest/common.h>
#include <ssl/mp.h>
#include <limits.h>

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

//TODO make seperate functions for the non-linear transformation functions
static void md5_transform(struct md5_ctx *ctx)
{
	u32 saved[4];

	ft_memcpy(saved, ctx->state, sizeof(saved));

	for (int i = 0; i < 64; i++) {
		u32 f, g;

		if (i < 16) {
			f = (saved[MD5_B] & saved[MD5_C]) |
			    ((~saved[MD5_B]) & saved[MD5_D]);
			g = i;
		} else if (i < 32) {
			f = (saved[MD5_D] & saved[MD5_B]) |
			    ((~saved[MD5_D]) & saved[MD5_C]);
			g = ((i * 5) + 1) % 16;
		} else if (i < 48) {
			f = saved[MD5_B] ^ saved[MD5_C] ^ saved[MD5_D];
			g = ((i * 3) + 5) % 16;
		} else {
			f = saved[MD5_C] ^ (saved[MD5_B] | (~saved[MD5_D]));
			g = (i * 7) % 16;
		}

		f = f + saved[MD5_A] + MD5_K[i] + from_le32(ctx->chunk.words[g]);

		saved[MD5_A] = saved[MD5_D];
		saved[MD5_D] = saved[MD5_C];
		saved[MD5_C] = saved[MD5_B];
		saved[MD5_B] = saved[MD5_B] + ssl_rotleft32(f, MD5_ROTTABLE[i]);
	}

	for (int i = 0; i < 4; i++)
		ctx->state[i] += saved[i];
}

void md5_init(struct md5_ctx *ctx)
{
	ft_memset(&ctx->chunk, 0, sizeof(ctx->chunk));

	ctx->state[MD5_A] = 0x67452301;
	ctx->state[MD5_B] = 0xefcdab89;
	ctx->state[MD5_C] = 0x98badcfe;
	ctx->state[MD5_D] = 0x10325476;

	ctx->offset = 0;
	mp_init(ctx->nwritten, sizeof(ctx->nwritten));
}

static void md5_transform_wrapper(void *p)
{
	md5_transform(p);
}

void md5_update(struct md5_ctx *ctx, const void *buf, size_t n)
{
	dgst_generic_update(ctx->chunk.bytes, sizeof(ctx->chunk), &ctx->offset,
			    buf, n, md5_transform_wrapper, ctx);
	mp_add(ctx->nwritten, sizeof(ctx->nwritten), n * CHAR_BIT);
}

static void md5_pad(struct md5_ctx *ctx)
{
	dgst_generic_pad(ctx->chunk.bytes, sizeof(ctx->chunk), ctx->nwritten,
			 sizeof(ctx->nwritten), ctx->offset, ENDIAN_LITTLE,
			 md5_transform_wrapper, ctx);
}

void md5_final(struct md5_ctx *ctx, unsigned char *dest)
{
	md5_pad(ctx);

	ft_memcpy(dest, ctx->state, sizeof(ctx->state));
}
