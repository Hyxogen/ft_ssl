#ifndef COMMON_BITOPS_H
#define COMMON_BITOPS_H

#include <stdint.h>
#include <assert.h>

#if defined __has_attribute
#if __has_attribute(const)
#define CONST __attribute__((const))
#else
#define CONST
#endif
#else
#define CONST
#endif

//https://blog.regehr.org/archives/1063
CONST static inline uint32_t rotleft32(uint32_t val, uint8_t amount)
{
	assert(amount < 32);
	return (val << amount) | (val >> (-amount&31));
}

CONST static inline uint32_t rotright32(uint32_t val, uint8_t amount)
{
	assert(amount < 32);
	return (val >> amount) | (val << (-amount&31));
}

CONST static inline uint64_t rotleft64(uint64_t val, uint8_t amount)
{
	assert(amount < 64);
	return (val << amount) | (val >> (-amount&63));
}

CONST static inline uint64_t rotright64(uint64_t val, uint8_t amount)
{
	assert(amount < 64);
	return (val >> amount) | (val << (-amount&63));
}

#endif
