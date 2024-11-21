#include <ssl/types.h>
#include <ssl/math.h>
#include <ft/string.h>
#include <stdbool.h>
#include <common/endian.h>

/* TODO remove */
#include <stdio.h>

#define Nk 4
#define Nr 10
/* https://www.youtube.com/watch?v=x1v2tX4_dkQ */
/* https://www.youtube.com/watch?v=NHuibtoL_qk */

static const u8 SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
};

static void add_round_key(u8 state[4][4], const u32 round_key[4])
{
	for (u8 c = 0; c < 4; c++) {
		union {
			u32 word;
			u8 bytes[4];
		} u;

		u.bytes[0] = state[0][c];
		u.bytes[1] = state[1][c];
		u.bytes[2] = state[2][c];
		u.bytes[3] = state[3][c];

		u32 val = u.word ^ round_key[c];

		u.word = val;

		state[0][c] = u.bytes[0];
		state[1][c] = u.bytes[1];
		state[2][c] = u.bytes[2];
		state[3][c] = u.bytes[3];
	}
}

static void sub_bytes(u8 state[4][4])
{
	for (u8 row = 0; row < 4; row++) {
		for (u8 col = 0; col < 4; col++) {
			state[row][col] = SBOX[state[row][col]];
		}
	}
}

static void shift_row(u8 row[4], u8 amount)
{
	for (u8 i = 0; i < amount; i++) {
		u8 temp = row[0];
		row[0] = row[1];
		row[1] = row[2];
		row[2] = row[3];
		row[3] = temp;
	}
}

static void shift_rows(u8 state[4][4])
{
	shift_row(state[1], 1);
	shift_row(state[2], 2);
	shift_row(state[3], 3);
}

static void mix_column(u8 column[4])
{
	u8 copy[4];
	u8 mul2[4];

	for (u8 i = 0; i < 4; i++) {
		copy[i] = column[i];

		bool high = column[i] >> 7;

		mul2[i] = column[i] << 1;
		mul2[i] ^= high * 0x1b;
	}

	column[0] = mul2[0] ^ copy[3] ^ copy[2] ^ mul2[1] ^ copy[1];
	column[1] = mul2[1] ^ copy[0] ^ copy[3] ^ mul2[2] ^ copy[2];
	column[2] = mul2[2] ^ copy[1] ^ copy[0] ^ mul2[3] ^ copy[3];
	column[3] = mul2[3] ^ copy[2] ^ copy[1] ^ mul2[0] ^ copy[0];
}

static void mix_columns(u8 state[4][4])
{
	for (u8 col = 0; col < 4; col++) {
		u8 column[4] = {state[0][col], state[1][col], state[2][col],
				state[3][col]};

		mix_column(column);

		state[0][col] = column[0];
		state[1][col] = column[1];
		state[2][col] = column[2];
		state[3][col] = column[3];
	}
}

static u32 rot_word(u32 word)
{
	return ssl_rotleft32(word, 8);
}

static u32 sub_word(u32 word)
{
	union {
		u32 word;
		u8 bytes[4];
	} u;

	u.word = word;

	u.bytes[0] = SBOX[u.bytes[0]];
	u.bytes[1] = SBOX[u.bytes[1]];
	u.bytes[2] = SBOX[u.bytes[2]];
	u.bytes[3] = SBOX[u.bytes[3]];

	return u.word;
}

static const u32 Rcon[10] = {
	0x01000000,
	0x02000000,
	0x04000000,
	0x08000000,
	0x10000000,
	0x20000000,
	0x40000000,
	0x80000000,
	0x1b000000,
	0x36000000,
};

static void key_expansion(u32 w[(Nr + 1) * 4], const u8 key[16])
{
	u8 i = 0;

	while (i <= (Nk - 1)) {
		w[i] = from_be32(*(u32 *)&key[4 * i]);
		i += 1;
	}

	while (i <=  (4 * Nr + 3)) {
		u32 temp = w[i - 1];

		if ((i % Nk) == 0) {
			temp = sub_word(rot_word(temp)) ^ Rcon[(i/Nk)-1];
		} else if (Nk > 6 && (i % Nk) == 4) {
			temp = sub_word(temp);
		}

		w[i] = w[i - Nk] ^ temp;

		i += 1;
	}

	for (i = 0; i < (Nr + 1) * 4; i++) {
		w[i] = from_be32(w[i]);
	}
}

static void copy_to_state(u8 state[4][4], const u8 in[16])
{
	for (u8 row = 0; row < 4; row++) {
		for (u8 col = 0; col < 4; col++) {
			state[row][col] = in[row + 4 * col];
		}
	}

}

static void copy_from_state(u8 dest[16], const u8 state[4][4])
{
	for (u8 row = 0; row < 4; row++) {
		for (u8 col = 0; col < 4; col++) {
			dest[row + 4 * col] = state[row][col];
		}
	}
}

static void dump_state(const u8 state[4][4])
{
	for (u8 row = 0; row < 4; row++) {
		for (u8 col = 0; col < 4; col++) {
			printf("%02hhx ", state[row][col]);
		}
		printf("\n");
	}
	printf("\n");
}

static void dump_round_key(const u32 round_keys[4])
{
	dump_state((void*) round_keys);
}

static void dump_round_keys(const u32 keys[(Nr + 1) * 4])
{
	for (unsigned i = 0; i < (Nr + 1) * 4; i++) {
		printf("w(%02u) = 0x%08x\n", i, keys[i]);
	}
}

void do_chipher(u8 block[16], const u8 key[16], u8 rounds)
{
	u8 state[4][4];
	u32 round_keys[(Nr + 1) * 4];

	copy_to_state(state, block);

	key_expansion(round_keys, key);

	dump_round_keys(round_keys);

	dump_state(state);
	printf("round key\n");
	dump_round_key(&round_keys[0]);

	add_round_key(state, &round_keys[0]);

	for (u8 i = 1; i < rounds; i++) {
		printf("start of round %u\n", i);
		dump_state(state);

		sub_bytes(state);
		printf("after subbytes\n");
		dump_state(state);

		shift_rows(state);
		printf("after shift_rows\n");
		dump_state(state);

		mix_columns(state);
		printf("after mix_columns\n");
		dump_state(state);

		add_round_key(state, &round_keys[i * 4]);

		printf("round key\n");
		dump_round_key(&round_keys[i * 4]);
	}

	sub_bytes(state);
	shift_rows(state);
	add_round_key(state, &round_keys[4*Nr]);

	dump_state(state);
	copy_from_state(block, state);
}
