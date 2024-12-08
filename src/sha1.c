#include <ssl/digest/sha1.h>
#include <common/endian.h>
#include <common/bitops.h>
#include <ft/string.h>
#include <assert.h>

#define SHA1_A 0
#define SHA1_B 1
#define SHA1_C 2
#define SHA1_D 3
#define SHA1_E 4
#define SHA1_ROUNDS 80

static_assert(CHAR_BIT % 8 == 0, "weird bits per byte");

void sha1_init(struct sha1_ctx *ctx)
{
	ctx->state[SHA1_A] = 0x67452301;
	ctx->state[SHA1_B] = 0xefcdab89;
	ctx->state[SHA1_C] = 0x98badcfe;
	ctx->state[SHA1_D] = 0x10325476;
	ctx->state[SHA1_E] = 0xc3d2e1f0;

	ctx->offset = 0;
	ctx->nwritten = 0;
}

static void sha1_generate_w(u32 dest[SHA1_ROUNDS],
			    const unsigned char block[SHA1_BLOCK_LEN])
{
	for (unsigned i = 0, j = 0; j < SHA1_BLOCK_LEN;
	     i++, j += sizeof(u32)) {
		dest[i] = from_be32(&block[j]);
	}

	for (unsigned t = 16; t < SHA1_ROUNDS; t++) {
		dest[t] = rotleft32(
		    dest[t - 3] ^ dest[t - 8] ^ dest[t - 14] ^ dest[t - 16], 1);
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

static void sha1_transform(u32 state[static 5],
			   const unsigned char block[static SHA1_BLOCK_LEN])
{
	u32 saved[5];
	ft_memcpy(saved, state, sizeof(saved));

	u32 w[SHA1_ROUNDS];
	sha1_generate_w(w, block);

	for (unsigned t = 0; t < SHA1_ROUNDS; t++) {
		u32 f;
		u32 k;

		if (t < 20) {
			f = sha1_f1(state[SHA1_B], state[SHA1_C], state[SHA1_D]);
			k = 0x5a827999;
		} else if (t < 40) {
			f = sha1_f2(state[SHA1_B], state[SHA1_C], state[SHA1_D]);
			k = 0x6ed9eba1;
		} else if (t < 60) {
			f = sha1_f3(state[SHA1_B], state[SHA1_C], state[SHA1_D]);
			k = 0x8f1bbcdc;
		} else {
			f = sha1_f4(state[SHA1_B], state[SHA1_C], state[SHA1_D]);
			k = 0xca62c1d6;
		}

		u32 temp = rotleft32(state[SHA1_A], 5) + f + state[SHA1_E] + w[t] + k;

		state[SHA1_E] = state[SHA1_D];
		state[SHA1_D] = state[SHA1_C];
		state[SHA1_C] = rotleft32(state[SHA1_B], 30);
		state[SHA1_B] = state[SHA1_A];
		state[SHA1_A] = temp;
	}

	for (unsigned i = 0; i < 5; i++) {
		state[i] += saved[i];
	}
}

void sha1_update(struct sha1_ctx *ctx, const void *buf, size_t n)
{
	const unsigned char *cbuf = buf;

	for (size_t i = 0; i < n; i++) {
		ctx->block[ctx->offset++] = cbuf[i];

		if (ctx->offset >= SHA1_BLOCK_LEN) {
			sha1_transform(ctx->state, ctx->block);
			ctx->offset = 0;
		}
	}

	ctx->nwritten += n * CHAR_BIT;
}

static const u8 sha1_padding[128] = {0x80};

static void sha1_do_pad(struct sha1_ctx *ctx)
{
	size_t padding = 1; /* 1 for the 0x80 byte */

	size_t offset = ctx->offset;
	offset = (offset + 1) % SHA1_BLOCK_LEN;

	size_t stop = SHA1_BLOCK_LEN - sizeof(ctx->nwritten);
	if (offset > stop) {
		padding += SHA1_BLOCK_LEN - offset;
		padding += stop;
	} else {
		padding += stop - offset;
	}

	unsigned char length[sizeof(u64)];
	to_be64(length, ctx->nwritten);

	sha1_update(ctx, sha1_padding, padding);
	sha1_update(ctx, length, sizeof(length));
}

static void sha1_create_hash(unsigned char dest[SHA1_DIGEST_LEN],
			    const u32 state[static 5])
{
	for (size_t i = 0; i < 5; i++) {
		to_be32(&dest[i * sizeof(u32)], state[i]);
	}
}

void sha1_final(unsigned char dest[SHA1_DIGEST_LEN], struct sha1_ctx *ctx)
{
	sha1_do_pad(ctx);
	sha1_create_hash(dest, ctx->state);
}
