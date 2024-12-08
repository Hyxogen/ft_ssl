#include <ssl/digest/sha2.h>
#include <common/bitops.h>
#include <common/endian.h>
#include <ft/string.h>
#include <assert.h>
#include <limits.h>

#define SHA2_A 0
#define SHA2_B 1
#define SHA2_C 2
#define SHA2_D 3
#define SHA2_E 4
#define SHA2_F 5
#define SHA2_G 6
#define SHA2_H 7

static_assert(CHAR_BIT % 8 == 0, "weird bits per byte");

/*
	#!/usr/bin/python
	from gmpy2 import next_prime, mpfr, floor

	def gen_primes(n=64):
	    p = 2
	    i = 0
	    while i < n:
		yield p
		p = next_prime(p)
		i += 1

	def convert_prime(prime):
	    cuberoot = mpfr(prime)**(1/mpfr(3))

	    frac = cuberoot - floor(cuberoot)
	    return "%08x" % int(floor(frac * (16 **8)))

	print("static const u32 SHA256_K[64] = {")
	for p in gen_primes(64):
	    print("0x{}, ".format(convert_prime(p)))
	print("};")
*/

static const u32 SHA256_K[SHA256_ROUNDS] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

void sha256_init(struct sha256_ctx *ctx)
{
	ctx->state[SHA2_A] = 0x6a09e667;
	ctx->state[SHA2_B] = 0xbb67ae85;
	ctx->state[SHA2_C] = 0x3c6ef372;
	ctx->state[SHA2_D] = 0xa54ff53a;
	ctx->state[SHA2_E] = 0x510e527f;
	ctx->state[SHA2_F] = 0x9b05688c;
	ctx->state[SHA2_G] = 0x1f83d9ab;
	ctx->state[SHA2_H] = 0x5be0cd19;

	ctx->offset = 0;
	ctx->nwritten = 0;
}

static u32 do_Ch(u32 x, u32 y, u32 z)
{
	return (x & y) ^ ((~x) & z);
}

static u32 Maj(u32 x, u32 y, u32 z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

static u32 Sigma0(u32 x)
{
	return rotright32(x, 2) ^ rotright32(x, 13) ^
	       rotright32(x, 22);
}

static u32 Sigma1(u32 x)
{
	return rotright32(x, 6) ^ rotright32(x, 11) ^
	       rotright32(x, 25);
}

static u32 Sigmoid0(u32 x)
{
	return rotright32(x, 7) ^ rotright32(x, 18) ^ (x >> 3);
}

static u32 Sigmoid1(u32 x)
{
	return rotright32(x, 17) ^ rotright32(x, 19) ^ (x >> 10);
}

static void sha256_generate_w(u32 dest[SHA256_ROUNDS],
			      const unsigned char block[SHA256_BLOCK_LEN])
{
	for (unsigned i = 0, j = 0; j < SHA256_BLOCK_LEN;
	     i++, j += sizeof(u32)) {
		dest[i] = from_be32(&block[j]);
	}

	for (unsigned j = 16; j < SHA256_ROUNDS; j++) {
		dest[j] = Sigmoid1(dest[j - 2]) + dest[j - 7] +
			  Sigmoid0(dest[j - 15]) + dest[j - 16];
	}
}

static void sha256_transform(u32 state[static 8],
			     const unsigned char block[static SHA256_BLOCK_LEN])
{
	u32 saved[8];
	ft_memcpy(saved, state, sizeof(saved));

	u32 w[SHA256_ROUNDS];
	sha256_generate_w(w, block);

	for (unsigned j = 0; j < SHA256_ROUNDS; j++) {
		u32 Wj = w[j];

		u32 T1 = state[SHA2_H] + Sigma1(state[SHA2_E]) +
			 do_Ch(state[SHA2_E], state[SHA2_F], state[SHA2_G]) + SHA256_K[j] + Wj;
		u32 T2 = Sigma0(state[SHA2_A]) + Maj(state[SHA2_A], state[SHA2_B], state[SHA2_C]);

		state[SHA2_H] = state[SHA2_G];
		state[SHA2_G] = state[SHA2_F];
		state[SHA2_F] = state[SHA2_E];
		state[SHA2_E] = state[SHA2_D] + T1;
		state[SHA2_D] = state[SHA2_C];
		state[SHA2_C] = state[SHA2_B];
		state[SHA2_B] = state[SHA2_A];
		state[SHA2_A] = T1 + T2;
	}

	for (unsigned i = 0; i < 8; i++) {
		state[i] += saved[i];
	}
}

void sha256_update(struct sha256_ctx *ctx, const void *buf, size_t n)
{
	const unsigned char *cbuf = buf;

	for (size_t i = 0; i < n; i++) {
		ctx->block[ctx->offset++] = cbuf[i];

		if (ctx->offset >= SHA256_BLOCK_LEN) {
			sha256_transform(ctx->state, ctx->block);
			ctx->offset = 0;
		}
	}

	ctx->nwritten += n * CHAR_BIT;
}

static const u8 sha256_padding[128] = {0x80};

static void sha256_do_pad(struct sha256_ctx *ctx)
{
	size_t padding = 1; /* 1 for the 0x80 byte */

	size_t offset = ctx->offset;
	offset = (offset + 1) % SHA256_BLOCK_LEN;

	size_t stop = SHA256_BLOCK_LEN - sizeof(ctx->nwritten);
	if (offset > stop) {
		padding += SHA256_BLOCK_LEN - offset;
		padding += stop;
	} else {
		padding += stop - offset;
	}

	unsigned char length[8];
	to_be64(length, ctx->nwritten);

	sha256_update(ctx, sha256_padding, padding);
	sha256_update(ctx, length, sizeof(length));
}

static void sha256_create_hash(unsigned char dest[SHA256_DIGEST_LEN],
			    const u32 state[static 8])
{
	for (size_t i = 0; i < 8; i++) {
		to_be32(&dest[i * sizeof(u32)], state[i]);
	}
}

void sha256_final(unsigned char dest[SHA256_DIGEST_LEN], struct sha256_ctx *ctx)
{
	sha256_do_pad(ctx);
	sha256_create_hash(dest, ctx->state);
}
