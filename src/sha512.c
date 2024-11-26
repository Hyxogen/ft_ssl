#include <assert.h>
#include <common/endian.h>
#include <ft/string.h>
#include <limits.h>
#include <ssl/math.h>
#include <ssl/sha2.h>

static_assert(CHAR_BIT == 8, "this code expects 8 bit bytes");

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
	return ssl_rotright64(x, 28) ^ ssl_rotright64(x, 34) ^
	       ssl_rotright64(x, 39);
}

static u64 Sigma1(u64 x)
{
	return ssl_rotright64(x, 14) ^ ssl_rotright64(x, 18) ^
	       ssl_rotright64(x, 41);
}

static u64 Sigmoid0(u64 x)
{
	return ssl_rotright64(x, 1) ^ ssl_rotright64(x, 8) ^ (x >> 7);
}

static u64 Sigmoid1(u64 x)
{
	return ssl_rotright64(x, 19) ^ ssl_rotright64(x, 61) ^ (x >> 6);
}

static void sha512_generate_w(u64 dest[SHA512_ROUNDS],
			      const u8 block[SHA512_BLOCK_LEN])
{
	ft_memcpy(dest, block, SHA512_BLOCK_LEN);

	for (unsigned j = 0; j < 16; j++) {
		dest[j] = from_be64(dest[j]);
	}

	for (unsigned j = 16; j < SHA512_ROUNDS; j++) {
		dest[j] = Sigmoid1(dest[j - 2]) + dest[j - 7] +
			  Sigmoid0(dest[j - 15]) + dest[j - 16];
	}
}

static void sha512_compress(union sha512_hash *prev,
			    const u8 block[SHA512_BLOCK_LEN])
{
	u64 w[SHA512_ROUNDS];
	ft_memset(w, 0, sizeof(w));
	sha512_generate_w(w, block);

	for (unsigned j = 0; j < SHA512_ROUNDS; j++) {
		u64 Wj = w[j];

		u64 T1 = prev->h + Sigma1(prev->e) +
			 do_Ch(prev->e, prev->f, prev->g) + SHA512_K[j] + Wj;
		u64 T2 = Sigma0(prev->a) + Maj(prev->a, prev->b, prev->c);

		prev->h = prev->g;
		prev->g = prev->f;
		prev->f = prev->e;
		prev->e = prev->d + T1;
		prev->d = prev->c;
		prev->c = prev->b;
		prev->b = prev->a;
		prev->a = T1 + T2;
	}
}

static void sha512_update_hash(union sha512_hash *dest, const union sha512_hash *b)
{
	for (unsigned i = 0; i < SHA512_HASH_NUM_WORDS; i++) {
		dest->words[i] += b->words[i];
	}
}

static void sha512_transform(union sha512_hash *hash,
			     const u8 block[SHA512_BLOCK_LEN])
{
	union sha512_hash saved = *hash;

	sha512_compress(hash, block);
	sha512_update_hash(hash, &saved);
}

void sha512_init(struct sha512_ctx *ctx)
{
	ctx->hash.words[0] = 0x6a09e667f3bcc908;
	ctx->hash.words[1] = 0xbb67ae8584caa73b;
	ctx->hash.words[2] = 0x3c6ef372fe94f82b;
	ctx->hash.words[3] = 0xa54ff53a5f1d36f1;
	ctx->hash.words[4] = 0x510e527fade682d1;
	ctx->hash.words[5] = 0x9b05688c2b3e6c1f;
	ctx->hash.words[6] = 0x1f83d9abfb41bd6b;
	ctx->hash.words[7] = 0x5be0cd19137e2179;

	ctx->nwritten[0] = 0;
	ctx->nwritten[1] = 0;
}

size_t sha512_update(struct sha512_ctx *ctx, const void *buf, size_t n)
{
	assert((ctx->nwritten[0] % CHAR_BIT) == 0);
	size_t offset = ((ctx->nwritten[0] / CHAR_BIT) % SHA512_BLOCK_LEN);
	size_t left = SHA512_BLOCK_LEN - offset;

	size_t to_copy = left > n ? n : left;

	ft_memcpy(&ctx->block[offset], buf, to_copy);

	u64 saved = ctx->nwritten[0];
	ctx->nwritten[0] += to_copy * CHAR_BIT;

	if (ctx->nwritten[0] < saved)
		ctx->nwritten[1] += 1;

	if (to_copy == left) {
		sha512_transform(&ctx->hash, ctx->block);
	}

	return to_copy;
}

static void sha512_do_pad(struct sha512_ctx *ctx)
{
	/* length is in bits and has to be saved here, as sha512_update
	 * will change it*/
	u64 saved[2];

	ft_memcpy(saved, ctx->nwritten, sizeof(saved));

	sha512_update(ctx, "\x80", 1);

	while (((ctx->nwritten[0] / CHAR_BIT) % SHA512_BLOCK_LEN) !=
	       (SHA512_BLOCK_LEN - sizeof(saved)))
		sha512_update(ctx, "\x00", 1);

	saved[0] = to_be64(saved[0]);
	saved[1] = to_be64(saved[1]);

	sha512_update(ctx, &saved[1], sizeof(saved[1]));
	sha512_update(ctx, &saved[0], sizeof(saved[0]));
}

static void sha512_create_hash(unsigned char *dest, const union sha512_hash *hash)
{
	u64 *dest64 = (void*) dest;

	for (unsigned i = 0; i < SHA512_HASH_NUM_WORDS; i++) {
		*dest64++ = to_be64(hash->words[i]);
	}
}

void sha512_final(struct sha512_ctx *ctx, unsigned char *dest)
{
	sha512_do_pad(ctx);
	sha512_create_hash(dest, &ctx->hash);
}
