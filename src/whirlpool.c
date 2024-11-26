#include <ssl/types.h>
#include <ssl/whirlpool.h>
#include <ft/string.h>
#include <common/endian.h>
#include <ssl/mp.h>

#define WHIRLPOOL_NROUNDS 10

/* TODO check if we can make the table textually smaller */
static const u8 RCON[WHIRLPOOL_NROUNDS + 1][W_BLOCK_SIZE] = {
    {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    },
    {
	0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    },
    {
	0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    },
    {
	0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    },
    {
	0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    },
    {
	0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    },
    {
	0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    },
    {
	0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    },
    {
	0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    },
    {
	0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    },
    {
	0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    },
};

static const u8 SBOX[256] = {
    0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5,
    0x79, 0x6f, 0x91, 0x52, 0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35,
    0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57, 0x15, 0x77, 0x37, 0xe5,
    0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
    0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b,
    0xa7, 0x7d, 0x95, 0xd8, 0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e,
    0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33, 0x63, 0x02, 0xaa, 0x71,
    0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
    0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f,
    0x20, 0x68, 0x1a, 0xae, 0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12,
    0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d, 0x97, 0x00, 0xcf, 0x2b,
    0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
    0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d,
    0x92, 0x75, 0x06, 0x8a, 0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96,
    0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c, 0x5e, 0x78, 0x38, 0x8c,
    0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
    0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11,
    0x8f, 0x4e, 0xb7, 0xeb, 0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3,
    0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9, 0x2a, 0xbb, 0xc1, 0x53,
    0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
    0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4,
    0x28, 0x5c, 0xf8, 0x86,
};

static const u8 MUL2[256] = {
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16,
    0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e,
    0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e, 0x40, 0x42, 0x44, 0x46,
    0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
    0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76,
    0x78, 0x7a, 0x7c, 0x7e, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e,
    0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e, 0xa0, 0xa2, 0xa4, 0xa6,
    0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
    0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6,
    0xd8, 0xda, 0xdc, 0xde, 0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
    0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe, 0x1d, 0x1f, 0x19, 0x1b,
    0x15, 0x17, 0x11, 0x13, 0x0d, 0x0f, 0x09, 0x0b, 0x05, 0x07, 0x01, 0x03,
    0x3d, 0x3f, 0x39, 0x3b, 0x35, 0x37, 0x31, 0x33, 0x2d, 0x2f, 0x29, 0x2b,
    0x25, 0x27, 0x21, 0x23, 0x5d, 0x5f, 0x59, 0x5b, 0x55, 0x57, 0x51, 0x53,
    0x4d, 0x4f, 0x49, 0x4b, 0x45, 0x47, 0x41, 0x43, 0x7d, 0x7f, 0x79, 0x7b,
    0x75, 0x77, 0x71, 0x73, 0x6d, 0x6f, 0x69, 0x6b, 0x65, 0x67, 0x61, 0x63,
    0x9d, 0x9f, 0x99, 0x9b, 0x95, 0x97, 0x91, 0x93, 0x8d, 0x8f, 0x89, 0x8b,
    0x85, 0x87, 0x81, 0x83, 0xbd, 0xbf, 0xb9, 0xbb, 0xb5, 0xb7, 0xb1, 0xb3,
    0xad, 0xaf, 0xa9, 0xab, 0xa5, 0xa7, 0xa1, 0xa3, 0xdd, 0xdf, 0xd9, 0xdb,
    0xd5, 0xd7, 0xd1, 0xd3, 0xcd, 0xcf, 0xc9, 0xcb, 0xc5, 0xc7, 0xc1, 0xc3,
    0xfd, 0xff, 0xf9, 0xfb, 0xf5, 0xf7, 0xf1, 0xf3, 0xed, 0xef, 0xe9, 0xeb,
    0xe5, 0xe7, 0xe1, 0xe3,
};

static const u8 MUL4[256] = {
    0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28, 0x2c,
    0x30, 0x34, 0x38, 0x3c, 0x40, 0x44, 0x48, 0x4c, 0x50, 0x54, 0x58, 0x5c,
    0x60, 0x64, 0x68, 0x6c, 0x70, 0x74, 0x78, 0x7c, 0x80, 0x84, 0x88, 0x8c,
    0x90, 0x94, 0x98, 0x9c, 0xa0, 0xa4, 0xa8, 0xac, 0xb0, 0xb4, 0xb8, 0xbc,
    0xc0, 0xc4, 0xc8, 0xcc, 0xd0, 0xd4, 0xd8, 0xdc, 0xe0, 0xe4, 0xe8, 0xec,
    0xf0, 0xf4, 0xf8, 0xfc, 0x1d, 0x19, 0x15, 0x11, 0x0d, 0x09, 0x05, 0x01,
    0x3d, 0x39, 0x35, 0x31, 0x2d, 0x29, 0x25, 0x21, 0x5d, 0x59, 0x55, 0x51,
    0x4d, 0x49, 0x45, 0x41, 0x7d, 0x79, 0x75, 0x71, 0x6d, 0x69, 0x65, 0x61,
    0x9d, 0x99, 0x95, 0x91, 0x8d, 0x89, 0x85, 0x81, 0xbd, 0xb9, 0xb5, 0xb1,
    0xad, 0xa9, 0xa5, 0xa1, 0xdd, 0xd9, 0xd5, 0xd1, 0xcd, 0xc9, 0xc5, 0xc1,
    0xfd, 0xf9, 0xf5, 0xf1, 0xed, 0xe9, 0xe5, 0xe1, 0x3a, 0x3e, 0x32, 0x36,
    0x2a, 0x2e, 0x22, 0x26, 0x1a, 0x1e, 0x12, 0x16, 0x0a, 0x0e, 0x02, 0x06,
    0x7a, 0x7e, 0x72, 0x76, 0x6a, 0x6e, 0x62, 0x66, 0x5a, 0x5e, 0x52, 0x56,
    0x4a, 0x4e, 0x42, 0x46, 0xba, 0xbe, 0xb2, 0xb6, 0xaa, 0xae, 0xa2, 0xa6,
    0x9a, 0x9e, 0x92, 0x96, 0x8a, 0x8e, 0x82, 0x86, 0xfa, 0xfe, 0xf2, 0xf6,
    0xea, 0xee, 0xe2, 0xe6, 0xda, 0xde, 0xd2, 0xd6, 0xca, 0xce, 0xc2, 0xc6,
    0x27, 0x23, 0x2f, 0x2b, 0x37, 0x33, 0x3f, 0x3b, 0x07, 0x03, 0x0f, 0x0b,
    0x17, 0x13, 0x1f, 0x1b, 0x67, 0x63, 0x6f, 0x6b, 0x77, 0x73, 0x7f, 0x7b,
    0x47, 0x43, 0x4f, 0x4b, 0x57, 0x53, 0x5f, 0x5b, 0xa7, 0xa3, 0xaf, 0xab,
    0xb7, 0xb3, 0xbf, 0xbb, 0x87, 0x83, 0x8f, 0x8b, 0x97, 0x93, 0x9f, 0x9b,
    0xe7, 0xe3, 0xef, 0xeb, 0xf7, 0xf3, 0xff, 0xfb, 0xc7, 0xc3, 0xcf, 0xcb,
    0xd7, 0xd3, 0xdf, 0xdb,
};

static const u8 MUL5[256] = {
    0x00, 0x05, 0x0a, 0x0f, 0x14, 0x11, 0x1e, 0x1b, 0x28, 0x2d, 0x22, 0x27,
    0x3c, 0x39, 0x36, 0x33, 0x50, 0x55, 0x5a, 0x5f, 0x44, 0x41, 0x4e, 0x4b,
    0x78, 0x7d, 0x72, 0x77, 0x6c, 0x69, 0x66, 0x63, 0xa0, 0xa5, 0xaa, 0xaf,
    0xb4, 0xb1, 0xbe, 0xbb, 0x88, 0x8d, 0x82, 0x87, 0x9c, 0x99, 0x96, 0x93,
    0xf0, 0xf5, 0xfa, 0xff, 0xe4, 0xe1, 0xee, 0xeb, 0xd8, 0xdd, 0xd2, 0xd7,
    0xcc, 0xc9, 0xc6, 0xc3, 0x5d, 0x58, 0x57, 0x52, 0x49, 0x4c, 0x43, 0x46,
    0x75, 0x70, 0x7f, 0x7a, 0x61, 0x64, 0x6b, 0x6e, 0x0d, 0x08, 0x07, 0x02,
    0x19, 0x1c, 0x13, 0x16, 0x25, 0x20, 0x2f, 0x2a, 0x31, 0x34, 0x3b, 0x3e,
    0xfd, 0xf8, 0xf7, 0xf2, 0xe9, 0xec, 0xe3, 0xe6, 0xd5, 0xd0, 0xdf, 0xda,
    0xc1, 0xc4, 0xcb, 0xce, 0xad, 0xa8, 0xa7, 0xa2, 0xb9, 0xbc, 0xb3, 0xb6,
    0x85, 0x80, 0x8f, 0x8a, 0x91, 0x94, 0x9b, 0x9e, 0xba, 0xbf, 0xb0, 0xb5,
    0xae, 0xab, 0xa4, 0xa1, 0x92, 0x97, 0x98, 0x9d, 0x86, 0x83, 0x8c, 0x89,
    0xea, 0xef, 0xe0, 0xe5, 0xfe, 0xfb, 0xf4, 0xf1, 0xc2, 0xc7, 0xc8, 0xcd,
    0xd6, 0xd3, 0xdc, 0xd9, 0x1a, 0x1f, 0x10, 0x15, 0x0e, 0x0b, 0x04, 0x01,
    0x32, 0x37, 0x38, 0x3d, 0x26, 0x23, 0x2c, 0x29, 0x4a, 0x4f, 0x40, 0x45,
    0x5e, 0x5b, 0x54, 0x51, 0x62, 0x67, 0x68, 0x6d, 0x76, 0x73, 0x7c, 0x79,
    0xe7, 0xe2, 0xed, 0xe8, 0xf3, 0xf6, 0xf9, 0xfc, 0xcf, 0xca, 0xc5, 0xc0,
    0xdb, 0xde, 0xd1, 0xd4, 0xb7, 0xb2, 0xbd, 0xb8, 0xa3, 0xa6, 0xa9, 0xac,
    0x9f, 0x9a, 0x95, 0x90, 0x8b, 0x8e, 0x81, 0x84, 0x47, 0x42, 0x4d, 0x48,
    0x53, 0x56, 0x59, 0x5c, 0x6f, 0x6a, 0x65, 0x60, 0x7b, 0x7e, 0x71, 0x74,
    0x17, 0x12, 0x1d, 0x18, 0x03, 0x06, 0x09, 0x0c, 0x3f, 0x3a, 0x35, 0x30,
    0x2b, 0x2e, 0x21, 0x24,
};

static const u8 MUL8[256] = {
    0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58,
    0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8, 0xb0, 0xb8,
    0xc0, 0xc8, 0xd0, 0xd8, 0xe0, 0xe8, 0xf0, 0xf8, 0x1d, 0x15, 0x0d, 0x05,
    0x3d, 0x35, 0x2d, 0x25, 0x5d, 0x55, 0x4d, 0x45, 0x7d, 0x75, 0x6d, 0x65,
    0x9d, 0x95, 0x8d, 0x85, 0xbd, 0xb5, 0xad, 0xa5, 0xdd, 0xd5, 0xcd, 0xc5,
    0xfd, 0xf5, 0xed, 0xe5, 0x3a, 0x32, 0x2a, 0x22, 0x1a, 0x12, 0x0a, 0x02,
    0x7a, 0x72, 0x6a, 0x62, 0x5a, 0x52, 0x4a, 0x42, 0xba, 0xb2, 0xaa, 0xa2,
    0x9a, 0x92, 0x8a, 0x82, 0xfa, 0xf2, 0xea, 0xe2, 0xda, 0xd2, 0xca, 0xc2,
    0x27, 0x2f, 0x37, 0x3f, 0x07, 0x0f, 0x17, 0x1f, 0x67, 0x6f, 0x77, 0x7f,
    0x47, 0x4f, 0x57, 0x5f, 0xa7, 0xaf, 0xb7, 0xbf, 0x87, 0x8f, 0x97, 0x9f,
    0xe7, 0xef, 0xf7, 0xff, 0xc7, 0xcf, 0xd7, 0xdf, 0x74, 0x7c, 0x64, 0x6c,
    0x54, 0x5c, 0x44, 0x4c, 0x34, 0x3c, 0x24, 0x2c, 0x14, 0x1c, 0x04, 0x0c,
    0xf4, 0xfc, 0xe4, 0xec, 0xd4, 0xdc, 0xc4, 0xcc, 0xb4, 0xbc, 0xa4, 0xac,
    0x94, 0x9c, 0x84, 0x8c, 0x69, 0x61, 0x79, 0x71, 0x49, 0x41, 0x59, 0x51,
    0x29, 0x21, 0x39, 0x31, 0x09, 0x01, 0x19, 0x11, 0xe9, 0xe1, 0xf9, 0xf1,
    0xc9, 0xc1, 0xd9, 0xd1, 0xa9, 0xa1, 0xb9, 0xb1, 0x89, 0x81, 0x99, 0x91,
    0x4e, 0x46, 0x5e, 0x56, 0x6e, 0x66, 0x7e, 0x76, 0x0e, 0x06, 0x1e, 0x16,
    0x2e, 0x26, 0x3e, 0x36, 0xce, 0xc6, 0xde, 0xd6, 0xee, 0xe6, 0xfe, 0xf6,
    0x8e, 0x86, 0x9e, 0x96, 0xae, 0xa6, 0xbe, 0xb6, 0x53, 0x5b, 0x43, 0x4b,
    0x73, 0x7b, 0x63, 0x6b, 0x13, 0x1b, 0x03, 0x0b, 0x33, 0x3b, 0x23, 0x2b,
    0xd3, 0xdb, 0xc3, 0xcb, 0xf3, 0xfb, 0xe3, 0xeb, 0x93, 0x9b, 0x83, 0x8b,
    0xb3, 0xbb, 0xa3, 0xab,
};

static const u8 MUL9[256] = {
    0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f, 0x48, 0x41, 0x5a, 0x53,
    0x6c, 0x65, 0x7e, 0x77, 0x90, 0x99, 0x82, 0x8b, 0xb4, 0xbd, 0xa6, 0xaf,
    0xd8, 0xd1, 0xca, 0xc3, 0xfc, 0xf5, 0xee, 0xe7, 0x3d, 0x34, 0x2f, 0x26,
    0x19, 0x10, 0x0b, 0x02, 0x75, 0x7c, 0x67, 0x6e, 0x51, 0x58, 0x43, 0x4a,
    0xad, 0xa4, 0xbf, 0xb6, 0x89, 0x80, 0x9b, 0x92, 0xe5, 0xec, 0xf7, 0xfe,
    0xc1, 0xc8, 0xd3, 0xda, 0x7a, 0x73, 0x68, 0x61, 0x5e, 0x57, 0x4c, 0x45,
    0x32, 0x3b, 0x20, 0x29, 0x16, 0x1f, 0x04, 0x0d, 0xea, 0xe3, 0xf8, 0xf1,
    0xce, 0xc7, 0xdc, 0xd5, 0xa2, 0xab, 0xb0, 0xb9, 0x86, 0x8f, 0x94, 0x9d,
    0x47, 0x4e, 0x55, 0x5c, 0x63, 0x6a, 0x71, 0x78, 0x0f, 0x06, 0x1d, 0x14,
    0x2b, 0x22, 0x39, 0x30, 0xd7, 0xde, 0xc5, 0xcc, 0xf3, 0xfa, 0xe1, 0xe8,
    0x9f, 0x96, 0x8d, 0x84, 0xbb, 0xb2, 0xa9, 0xa0, 0xf4, 0xfd, 0xe6, 0xef,
    0xd0, 0xd9, 0xc2, 0xcb, 0xbc, 0xb5, 0xae, 0xa7, 0x98, 0x91, 0x8a, 0x83,
    0x64, 0x6d, 0x76, 0x7f, 0x40, 0x49, 0x52, 0x5b, 0x2c, 0x25, 0x3e, 0x37,
    0x08, 0x01, 0x1a, 0x13, 0xc9, 0xc0, 0xdb, 0xd2, 0xed, 0xe4, 0xff, 0xf6,
    0x81, 0x88, 0x93, 0x9a, 0xa5, 0xac, 0xb7, 0xbe, 0x59, 0x50, 0x4b, 0x42,
    0x7d, 0x74, 0x6f, 0x66, 0x11, 0x18, 0x03, 0x0a, 0x35, 0x3c, 0x27, 0x2e,
    0x8e, 0x87, 0x9c, 0x95, 0xaa, 0xa3, 0xb8, 0xb1, 0xc6, 0xcf, 0xd4, 0xdd,
    0xe2, 0xeb, 0xf0, 0xf9, 0x1e, 0x17, 0x0c, 0x05, 0x3a, 0x33, 0x28, 0x21,
    0x56, 0x5f, 0x44, 0x4d, 0x72, 0x7b, 0x60, 0x69, 0xb3, 0xba, 0xa1, 0xa8,
    0x97, 0x9e, 0x85, 0x8c, 0xfb, 0xf2, 0xe9, 0xe0, 0xdf, 0xd6, 0xcd, 0xc4,
    0x23, 0x2a, 0x31, 0x38, 0x07, 0x0e, 0x15, 0x1c, 0x6b, 0x62, 0x79, 0x70,
    0x4f, 0x46, 0x5d, 0x54,
};

static void add_round_key(u8 block[W_BLOCK_SIZE], const u8 round_key[W_BLOCK_SIZE])
{
	for (unsigned i = 0; i < W_BLOCK_SIZE; i++) {
		block[i] = block[i] ^ round_key[i];
	}
}

static void sub_bytes(u8 block[W_BLOCK_SIZE])
{
	for (unsigned i = 0; i < W_BLOCK_SIZE; i++) {
		block[i] = SBOX[block[i]];
	}
}

static void shift_columns(u8 block[W_BLOCK_SIZE])
{
	u8 tmp[W_BLOCK_SIZE];

	ft_memcpy(tmp, block, W_BLOCK_SIZE);

	for (unsigned row = 0; row < 8; row++) {
		for (unsigned col = 0; col < 8; col++) {
			block[col + row * 8] = tmp[col + ((row - col) % 8) * 8];
		}
	}
}

static void mix_row(u8 row[8])
{
	u8 res[8];

	res[0] = row[0] ^ MUL9[row[1]] ^ MUL2[row[2]] ^ MUL5[row[3]] ^ MUL8[row[4]] ^ row[5] ^ MUL4[row[6]] ^ row[7];
	res[1] = row[0] ^ row[1] ^ MUL9[row[2]] ^ MUL2[row[3]] ^ MUL5[row[4]] ^ MUL8[row[5]] ^ row[6] ^ MUL4[row[7]];
	res[2] = MUL4[row[0]] ^ row[1] ^ row[2] ^ MUL9[row[3]] ^ MUL2[row[4]] ^ MUL5[row[5]] ^ MUL8[row[6]] ^ row[7];
	res[3] = row[0] ^ MUL4[row[1]] ^ row[2] ^ row[3] ^ MUL9[row[4]] ^ MUL2[row[5]] ^ MUL5[row[6]] ^ MUL8[row[7]];
	res[4] = MUL8[row[0]] ^ row[1] ^ MUL4[row[2]] ^ row[3] ^ row[4] ^ MUL9[row[5]] ^ MUL2[row[6]] ^ MUL5[row[7]];
	res[5] = MUL5[row[0]] ^ MUL8[row[1]] ^ row[2] ^ MUL4[row[3]] ^ row[4] ^ row[5] ^ MUL9[row[6]] ^ MUL2[row[7]];
	res[6] = MUL2[row[0]] ^ MUL5[row[1]] ^ MUL8[row[2]] ^ row[3] ^ MUL4[row[4]] ^ row[5] ^ row[6] ^ MUL9[row[7]];
	res[7] = MUL9[row[0]] ^ MUL2[row[1]] ^ MUL5[row[2]] ^ MUL8[row[3]] ^ row[4] ^ MUL4[row[5]] ^ row[6] ^ row[7];

	ft_memcpy(row, res, 8);
}

static void mix_rows(u8 block[W_BLOCK_SIZE])
{
	for (unsigned row = 0; row < 8; row++) {
		mix_row(&block[row * 8]);
	}
}

static void w_transform(u8 block[W_BLOCK_SIZE], const u8 round_key[W_BLOCK_SIZE])
{
	sub_bytes(block);
	shift_columns(block);
	mix_rows(block);
	add_round_key(block, round_key);
}

static void w_cipher(u8 block[W_BLOCK_SIZE], const u8 key[W_BLOCK_SIZE])
{
	u8 round_key[W_BLOCK_SIZE];

	ft_memcpy(round_key, key, sizeof(round_key));

	add_round_key(block, round_key);

	for (unsigned r = 1; r <= WHIRLPOOL_NROUNDS; r++) {
		w_transform(round_key, RCON[r]);
		w_transform(block, round_key);
	}
}

void whirlpool_init(struct whirlpool_ctx *ctx)
{
	ctx->offset = 0;
	ft_memset(ctx->hash, 0, W_BLOCK_SIZE);
	mp_init(ctx->nwritten, sizeof(ctx->nwritten));
}

static void whirlpool_transform(u8 hash[W_BLOCK_SIZE], const u8 block[W_BLOCK_SIZE])
{
	/* Miyaguchi-Preneel compression function */

	u8 cipher[W_BLOCK_SIZE];

	ft_memcpy(cipher, block, W_BLOCK_SIZE);
	w_cipher(cipher, hash);

	for (unsigned i = 0; i < W_BLOCK_SIZE; i++) {
		hash[i] ^= cipher[i] ^ block[i];
	}
}

size_t whirlpool_update(struct whirlpool_ctx *ctx, const void *buf, size_t n)
{
	size_t rem = W_BLOCK_SIZE - ctx->offset;

	if (rem < n)
		n = rem;

	ft_memcpy(&ctx->block[ctx->offset], buf, n);

	ctx->offset = (ctx->offset + n) % W_BLOCK_SIZE;
	/* TODO handle carry out */
	mp_add(ctx->nwritten, sizeof(ctx->nwritten), n * CHAR_BIT);

	if (n && !ctx->offset)
		whirlpool_transform(ctx->hash, ctx->block);

	return n;
}

static u8 zero[128];

static void whirlpool_do_pad(struct whirlpool_ctx *ctx)
{
	/* length is in bits and has to be saved here, as update
	 * will change it*/
	u8 saved[32];

	ft_memcpy(saved, ctx->nwritten, sizeof(saved));

	whirlpool_update(ctx, "\x80", 1);

	size_t stop = W_BLOCK_SIZE - sizeof(saved);
	if (ctx->offset > stop) {
		whirlpool_update(ctx, zero, W_BLOCK_SIZE - ctx->offset);
		whirlpool_update(ctx, zero, stop);
	} else if (ctx->offset < stop) {
		whirlpool_update(ctx, zero, stop - ctx->offset);
	}

	mp_encode(saved, sizeof(saved), ENDIAN_BIG);
	whirlpool_update(ctx, saved, sizeof(saved));
}

static void whirlpool_create_hash(unsigned char *dest,
				  const u8 hash[W_BLOCK_SIZE])
{
	ft_memcpy(dest, hash, W_BLOCK_SIZE);
}

void whirlpool_final(struct whirlpool_ctx *ctx, unsigned char *dest)
{
	whirlpool_do_pad(ctx);
	whirlpool_create_hash(dest, ctx->hash);
}
