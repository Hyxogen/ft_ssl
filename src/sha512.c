#include <ssl/digest/sha2.h>
#include <common/bitops.h>
#include <common/endian.h>
#include <ssl/mp.h>
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

#define SHA512_ROUNDS 80

static_assert(CHAR_BIT % 8 == 0, "weird bits per byte");

/*
#!/usr/bin/python
from gmpy2 import next_prime, mpfr, floor
import gmpy2

gmpy2.get_context().precision = 100

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
    return "%016x" % int(floor(frac * (16 ** 16)))

print("static const u64 SHA512_K[80] = {")
for p in gen_primes(80):
    print("0x{}, ".format(convert_prime(p)))
print("};")
*/
static const u64 SHA512_K[SHA512_ROUNDS] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

void sha512_init(struct sha512_ctx *ctx)
{
	ctx->state[SHA2_A] = 0x6a09e667f3bcc908;
	ctx->state[SHA2_B] = 0xbb67ae8584caa73b;
	ctx->state[SHA2_C] = 0x3c6ef372fe94f82b;
	ctx->state[SHA2_D] = 0xa54ff53a5f1d36f1;
	ctx->state[SHA2_E] = 0x510e527fade682d1;
	ctx->state[SHA2_F] = 0x9b05688c2b3e6c1f;
	ctx->state[SHA2_G] = 0x1f83d9abfb41bd6b;
	ctx->state[SHA2_H] = 0x5be0cd19137e2179;

	ctx->offset = 0;
	mp_init(ctx->nwritten, sizeof(ctx->nwritten));
}

static u64 do_Ch(u64 x, u64 y, u64 z)
{
	return (x & y) ^ ((~x) & z);
}

static u64 Maj(u64 x, u64 y, u64 z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

static u64 Sigma0(u64 x)
{
	return rotright64(x, 28) ^ rotright64(x, 34) ^
	       rotright64(x, 39);
}

static u64 Sigma1(u64 x)
{
	return rotright64(x, 14) ^ rotright64(x, 18) ^
	       rotright64(x, 41);
}

static u64 Sigmoid0(u64 x)
{
	return rotright64(x, 1) ^ rotright64(x, 8) ^ (x >> 7);
}

static u64 Sigmoid1(u64 x)
{
	return rotright64(x, 19) ^ rotright64(x, 61) ^ (x >> 6);
}

static void sha512_generate_w(u64 dest[SHA512_ROUNDS],
			      const unsigned char block[SHA512_BLOCK_LEN])
{
	for (unsigned i = 0, j = 0; j < SHA512_BLOCK_LEN;
	     i++, j += sizeof(u64)) {
		dest[i] = from_be64(&block[j]);
	}

	for (unsigned j = 16; j < SHA512_ROUNDS; j++) {
		dest[j] = Sigmoid1(dest[j - 2]) + dest[j - 7] +
			  Sigmoid0(dest[j - 15]) + dest[j - 16];
	}
}
static void sha512_transform(u64 state[static 8],
			     const unsigned char block[static SHA512_BLOCK_LEN])
{
	u64 saved[8];
	ft_memcpy(saved, state, sizeof(saved));

	u64 w[SHA512_ROUNDS];
	sha512_generate_w(w, block);

	for (unsigned j = 0; j < SHA512_ROUNDS; j++) {
		u64 Wj = w[j];

		u64 T1 = state[SHA2_H] + Sigma1(state[SHA2_E]) +
			 do_Ch(state[SHA2_E], state[SHA2_F], state[SHA2_G]) + SHA512_K[j] + Wj;
		u64 T2 = Sigma0(state[SHA2_A]) + Maj(state[SHA2_A], state[SHA2_B], state[SHA2_C]);

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

void sha512_update(struct sha512_ctx *ctx, const void *buf, size_t n)
{
	const unsigned char *cbuf = buf;

	for (size_t i = 0; i < n; i++) {
		ctx->block[ctx->offset++] = cbuf[i];

		if (ctx->offset >= SHA512_BLOCK_LEN) {
			sha512_transform(ctx->state, ctx->block);
			ctx->offset = 0;
		}
	}

	mp_add(ctx->nwritten, sizeof(ctx->nwritten), n * CHAR_BIT);
}

static const u8 sha512_padding[256] = {0x80};

static void sha512_do_pad(struct sha512_ctx *ctx)
{
	size_t padding = 1; /* 1 for the 0x80 byte */

	size_t offset = ctx->offset;
	offset = (offset + 1) % SHA512_BLOCK_LEN;

	size_t stop = SHA512_BLOCK_LEN - sizeof(ctx->nwritten);
	if (offset > stop) {
		padding += SHA512_BLOCK_LEN - offset;
		padding += stop;
	} else {
		padding += stop - offset;
	}

	unsigned char length[16];
	mp_encode(length, ctx->nwritten, sizeof(ctx->nwritten), ENDIAN_BIG);

	sha512_update(ctx, sha512_padding, padding);
	sha512_update(ctx, length, sizeof(length));
}

static void sha512_create_hash(unsigned char dest[SHA512_DIGEST_LEN],
			    const u64 state[static 8])
{
	for (size_t i = 0; i < 8; i++) {
		to_be64(&dest[i * sizeof(u64)], state[i]);
	}
}

void sha512_final(unsigned char dest[SHA512_DIGEST_LEN], struct sha512_ctx *ctx)
{
	sha512_do_pad(ctx);
	sha512_create_hash(dest, ctx->state);
}
