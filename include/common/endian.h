#ifndef COMMON_ENDIAN_H
#define COMMON_ENDIAN_H

#include <stdint.h>

enum endian {
	ENDIAN_LITTLE,
	ENDIAN_BIG,
};

static inline uint32_t from_le32(const unsigned char bytes[static 4])
{
	uint32_t res = 0;
	res |= (uint32_t) bytes[0] << 0;
	res |= (uint32_t) bytes[1] << 8;
	res |= (uint32_t) bytes[2] << 16;
	res |= (uint32_t) bytes[3] << 24;
	return res;
}

static inline uint32_t from_be32(const unsigned char bytes[static 4])
{
	uint32_t res = 0;
	res |= (uint32_t) bytes[3] << 0;
	res |= (uint32_t) bytes[2] << 8;
	res |= (uint32_t) bytes[1] << 16;
	res |= (uint32_t) bytes[0] << 24;
	return res;
}

static inline uint64_t from_be64(const unsigned char bytes[static 8])
{
	uint64_t res = 0;
	res |= (uint64_t) bytes[7] << 0;
	res |= (uint64_t) bytes[6] << 8;
	res |= (uint64_t) bytes[5] << 16;
	res |= (uint64_t) bytes[4] << 24;
	res |= (uint64_t) bytes[3] << 32;
	res |= (uint64_t) bytes[2] << 40;
	res |= (uint64_t) bytes[1] << 48;
	res |= (uint64_t) bytes[0] << 56;
	return res;
}

static inline void to_le32(unsigned char dest[static 4], uint32_t v)
{
	dest[0] = (v & 0x000000ff) >> 0;
	dest[1] = (v & 0x0000ff00) >> 8;
	dest[2] = (v & 0x00ff0000) >> 16;
	dest[3] = (v & 0xff000000) >> 24;
}

static inline void to_be32(unsigned char dest[static 4], uint32_t v)
{
	dest[3] = (v & 0x000000ff) >> 0;
	dest[2] = (v & 0x0000ff00) >> 8;
	dest[1] = (v & 0x00ff0000) >> 16;
	dest[0] = (v & 0xff000000) >> 24;
}

static inline void to_le64(unsigned char dest[static 8], uint64_t v)
{
	dest[0] = (v & 0x00000000000000ff) >> 0;
	dest[1] = (v & 0x000000000000ff00) >> 8;
	dest[2] = (v & 0x0000000000ff0000) >> 16;
	dest[3] = (v & 0x00000000ff000000) >> 24;
	dest[4] = (v & 0x000000ff00000000) >> 32;
	dest[5] = (v & 0x0000ff0000000000) >> 40;
	dest[6] = (v & 0x00ff000000000000) >> 48;
	dest[7] = (v & 0xff00000000000000) >> 56;
}

static inline void to_be64(unsigned char dest[static 8], uint64_t v)
{
	dest[7] = (v & 0x00000000000000ff) >> 0;
	dest[6] = (v & 0x000000000000ff00) >> 8;
	dest[5] = (v & 0x0000000000ff0000) >> 16;
	dest[4] = (v & 0x00000000ff000000) >> 24;
	dest[3] = (v & 0x000000ff00000000) >> 32;
	dest[2] = (v & 0x0000ff0000000000) >> 40;
	dest[1] = (v & 0x00ff000000000000) >> 48;
	dest[0] = (v & 0xff00000000000000) >> 56;
}

#endif
