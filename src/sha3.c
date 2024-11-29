#include <ssl/digest/sha3.h>
#include <ssl/digest/common.h>
#include <common/endian.h>
#include <ssl/math.h>

#ifdef FT_SSL_SHA3_DEBUG
/* TODO in ifdef */
#include <stdio.h>
#endif

#define KECCAK_NROUNDS 24
#define KECCAK_BLOCK_SIZE (5 * 5 * 8)

/* https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values */

/* TODO convert values for big endian when needed */
static const u64 KECCAK_RCON[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
};

static const u8 KECCAK_ROTTABLE[5][5] = {
    {0, 1, 62, 28, 27},	 {36, 44, 6, 55, 20}, {3, 10, 43, 25, 39},
    {41, 45, 15, 21, 8}, {18, 2, 61, 56, 14},
};

#ifdef FT_SSL_SHA3_DEBUG
#define debug_print(...) printf(__VA_ARGS__)
static void dump_state(const char *str, const u64 state[5][5])
{
	const u8 *bytes = (void*) state;
	debug_print("%s\n", str);

	for (unsigned i = 0; i < 200; i++) {
		if (i && i % 16 == 0)
			debug_print("\n");

		debug_print(" ");
		debug_print("%02hhX", bytes[i]);

	}
	debug_print("\n");
}
#else
#define debug_print(...) 
static void dump_state(const char *str, const u64 state[5][5])
{
	(void) str;
	(void) state;
}
#endif

static void keccak_f(u64 state[5][5])
{
	u64 b[5][5];
	u64 c[5];
	u64 d[5];

	dump_state("state before round functions:", state);

	for (unsigned r = 0; r < KECCAK_NROUNDS; r++) {
		debug_print("ROUND %u\n", r);


		/* theta */
		for (unsigned x = 0; x < 5; x++) {
			c[x] = state[0][x] ^ state[1][x] ^ state[2][x] ^
			       state[3][x] ^ state[4][x];
		}

		for (unsigned x = 0; x < 5; x++) {
			d[x] =
			    c[(x + 4) % 5] ^ ssl_rotleft64(c[(x + 1) % 5], 1);
		}

		for (unsigned y = 0; y < 5; y++) {
			for (unsigned x = 0; x < 5; x++) {
				state[y][x] ^= d[x];
			}
		}

		dump_state("after theta:", state);

		/* rho and pi */
		for (unsigned y = 0; y < 5; y++) {
			for (unsigned x = 0; x < 5; x++) {
				b[(2 * x + 3 * y) % 5][y] = ssl_rotleft64(
				    state[y][x], KECCAK_ROTTABLE[y][x]);
			}
		}

		dump_state("after rho and pi:", state);

		/* chi */
		for (unsigned y = 0; y < 5; y++) {
			for (unsigned x = 0; x < 5; x++) {
				state[y][x] = b[y][x] ^ ((~b[y][(x + 1) % 5]) &
							 b[y][(x + 2) % 5]);
			}
		}

		dump_state("after chi:", state);

		/* iota */
		state[0][0] ^= KECCAK_RCON[r];

		dump_state("after iota:", state);
		debug_print("\n");
	}
}

void sha3_init(struct sha3_ctx *ctx, unsigned mdlen)
{
	for (unsigned x = 0; x < 5; x++) {
		for (unsigned y = 0; y < 5; y++) {
			ctx->state.words[x][y] = 0;
		}
	}

	ctx->offset = 0;
	ctx->bitrate = 200 - 2 * mdlen;
}

static void sha3_transform(u64 state[5][5])
{
	/* TODO use different constants instead */
	for (unsigned x = 0; x < 5; x++) {
		for (unsigned y = 0; y < 5; y++) {
			state[x][y] = from_le64(state[x][y]);
		}
	}

	keccak_f(state);

	for (unsigned x = 0; x < 5; x++) {
		for (unsigned y = 0; y < 5; y++) {
			state[x][y] = to_le64(state[x][y]);
		}
	}
}

void sha3_update(struct sha3_ctx *ctx, const u8 *buf, size_t n)
{
	while (n--) {
		ctx->state.bytes[ctx->offset++] ^= *buf++;

		ctx->offset %= ctx->bitrate;
		if (!ctx->offset) {
			sha3_transform(ctx->state.words);
		}
	}
}

static void sha3_do_pad(struct sha3_ctx *ctx)
{
	ctx->state.bytes[ctx->offset] ^= 0x06;
	ctx->state.bytes[ctx->bitrate - 1] ^= 0x80;

	sha3_transform(ctx->state.words);

}

static void sha3_create_hash(unsigned char *dest, size_t mdlen, const struct sha3_ctx *ctx)
{
	if (mdlen > KECCAK_BLOCK_SIZE)
		mdlen = KECCAK_BLOCK_SIZE;

	u8* state = (void*) ctx->state.bytes;
	for (size_t i = 0; i < mdlen; i++) {
		dest[i] = state[i];
	}
}

void sha3_final(struct sha3_ctx *ctx, unsigned char *dest, size_t mdlen)
{
	sha3_do_pad(ctx);
	sha3_create_hash(dest, mdlen, ctx);
}
