#ifndef COMMON_ENDIAN_H
#define COMMON_ENDIAN_H

#ifndef __BYTE_ORDER__
# error "__BYTE_ORDER__ must be defined to use this header"
#else
#endif

#include <stdint.h>

enum endian {
	ENDIAN_LITTLE,
	ENDIAN_BIG,
};

static inline uint32_t byte_swap32(uint32_t v)
{
	uint32_t res = 0;

	res |= (v & 0x000000ff) << 24;
	res |= (v & 0x0000ff00) << 8;
	res |= (v & 0x00ff0000) >> 8;
	res |= (v & 0xff000000) >> 24;
	return res;
}

static inline uint64_t byte_swap64(uint64_t v)
{
	uint64_t res = 0;

	res |= (v & 0x00000000000000ff) << 56;
	res |= (v & 0x000000000000ff00) << 40;
	res |= (v & 0x0000000000ff0000) << 24;
	res |= (v & 0x00000000ff000000) << 8;

	res |= (v & 0x000000ff00000000) >> 8;
	res |= (v & 0x0000ff0000000000) >> 24;
	res |= (v & 0x00ff000000000000) >> 40;
	res |= (v & 0xff00000000000000) >> 56;
	return res;
}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

static inline uint32_t to_le32(uint32_t v)
{
	return v;
}

static inline uint32_t from_le32(uint32_t v)
{
	return v;
}

static inline uint64_t to_le64(uint64_t v)
{
	return v;
}

static inline uint64_t from_le64(uint64_t v)
{
	return v;
}

static inline uint32_t to_be32(uint32_t v)
{
	return byte_swap32(v);
}

static inline uint32_t from_be32(uint32_t v)
{
	return byte_swap32(v);
}

static inline uint64_t to_be64(uint64_t v)
{
	return byte_swap64(v);
}

static inline uint64_t from_be64(uint64_t v)
{
	return byte_swap64(v);
}

#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# error "TODO"
#else
# error "unsupported endiannes: " ##__BYTE_ORDER__
#endif

#endif
