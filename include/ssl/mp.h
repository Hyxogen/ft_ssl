#ifndef SSL_MP_H
#define SSL_MP_H

#include <ssl/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <common/endian.h>

void mp_init(u8 *string, size_t size);
/* returns if there was an carry out */
bool mp_add(u8 *string, size_t size, size_t amount);
void mp_encode(u8 *string, size_t size, enum endian endian); 

#endif
