#include <ssl/sha256.h>
#include <ssl/math.h>
#include <ft/string.h>
#include <common/endian.h>

#include <stdio.h>

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

static const u32 SHA256_K[64] = {
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

/* TODO pure attribute */
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
	return ssl_rotright32(x, 2) ^ ssl_rotright32(x, 13) ^ ssl_rotright32(x, 22);
}

static u32 Sigma1(u32 x)
{
	return ssl_rotright32(x, 6) ^ ssl_rotright32(x, 11) ^ ssl_rotright32(x, 25);
}

static u32 Sigmoid0(u32 x)
{
	return ssl_rotright32(x, 7) ^ ssl_rotright32(x, 18) ^ (x >> 3);
}

static u32 Sigmoid1(u32 x)
{
	return ssl_rotright32(x, 17) ^ ssl_rotright32(x, 19) ^ (x >> 10);
}

static void generate_w(u32 dest[64], const struct sha256_ctx *ctx)
{
	_Static_assert(sizeof(ctx->chunk) == (16 * sizeof(u32)), "basic assumption");
	ft_memcpy(dest, ctx->chunk.bytes, sizeof(ctx->chunk));

	for (unsigned j = 0; j < 16; j++) {
		dest[j] = from_be32(dest[j]);
	}

	for (unsigned j = 16; j < 64; j++) {
		dest[j] = Sigmoid1(dest[j - 2]) + dest[j - 7] +
			  Sigmoid0(dest[j - 15]) + dest[j - 16];
	}
}

static void sha256_dump(const union sha256_state *state)
{
	int first = 1;
	for (unsigned i = 0; i < 8; i++) {
		if (!first)
			fprintf(stderr, " ");
		first = 0;

		fprintf(stderr, "%08x", state->words[i]);
	}
}

static void process_chunk(struct sha256_ctx *ctx)
{
	union sha256_state saved = ctx->state;

	u32 w[64];
	generate_w(w, ctx);

	fprintf(stderr, "init:   ");
	sha256_dump(&saved);
	fprintf(stderr, "\n");

	for (unsigned j = 0; j < 64; j++) {
		u32 Wj = w[j];

		u32 T1 = saved.h + Sigma1(saved.e) +
			 do_Ch(saved.e, saved.f, saved.g) + SHA256_K[j] + Wj;
		u32 T2 = Sigma0(saved.a) + Maj(saved.a, saved.b, saved.c);

		saved.h = saved.g;
		saved.g = saved.f;
		saved.f = saved.e;
		saved.e = saved.d + T1;
		saved.d = saved.c;
		saved.c = saved.b;
		saved.b = saved.a;
		saved.a = T1 + T2;

		fprintf(stderr, "t = %02d  ", j);
		sha256_dump(&saved);
		fprintf(stderr, "\n");
	}

	for (unsigned i = 0; i < 8; i++) {
		ctx->state.words[i] += saved.words[i];
	}
}

int sha256_init(struct sha256_ctx *ctx)
{
	ctx->state.words[0] = 0x6a09e667;
	ctx->state.words[1] = 0xbb67ae85;
	ctx->state.words[2] = 0x3c6ef372;
	ctx->state.words[3] = 0xa54ff53a;
	ctx->state.words[4] = 0x510e527f;
	ctx->state.words[5] = 0x9b05688c;
	ctx->state.words[6] = 0x1f83d9ab;
	ctx->state.words[7] = 0x5be0cd19;

	ctx->nwritten = 0;
	return 0;
}

size_t sha256_write(struct sha256_ctx *ctx, const void *buf, size_t n)
{
	size_t offset = (ctx->nwritten % sizeof(ctx->chunk));
	size_t left = sizeof(ctx->chunk) - (offset);

	size_t to_copy = left > n ? n : left;

	ft_memcpy(&ctx->chunk.bytes[offset], buf, to_copy);
	ctx->nwritten += to_copy;

	if (to_copy == left)
		process_chunk(ctx);

	return to_copy;
}

static void do_pad(struct sha256_ctx *ctx)
{
	/* length is in bits and has to be calculated here, as sha256_write will
	 * change it*/
	u64 len = to_be64(ctx->nwritten << 3);

	sha256_write(ctx, "\x80", 1);

	while ((ctx->nwritten % 64) != 56)
		sha256_write(ctx, "\x00", 1);

	sha256_write(ctx, &len, sizeof(len));
}

size_t sha256_finalize(struct sha256_ctx *ctx, unsigned char *dest)
{
	do_pad(ctx);

	for (unsigned i = 0; i < 8; i++) {
		ctx->state.words[i] = to_be32(ctx->state.words[i]);
	}

	_Static_assert(sizeof(ctx->state) == 32, "basic assumption");
	ft_memcpy(dest, ctx->state.words, sizeof(ctx->state));
	return sizeof(ctx->state);
}
