#ifndef SSL_MP_H
#define SSL_MP_H

#include <ssl/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <common/endian.h>

void mp_init(u8 *string, size_t size);

/* returns true if there was an carry out */
bool mp_add(u8 *string, size_t size, size_t amount);
/* returns true if there was an carry in */
bool mp_sub(u8 *string, size_t size, size_t amount);

void mp_encode(unsigned char *restrict dest, const u8 *restrict string,
	       size_t size, enum endian endian);

#endif
