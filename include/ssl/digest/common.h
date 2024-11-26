#ifndef FT_SSL_DIGEST_COMMON_H
#define FT_SSL_DIGEST_COMMON_H

#include <ssl/types.h>

void dgst_generic_update(u8 *block, size_t block_size, size_t *offset,
			 const u8 *data, size_t nbytes,
			 void (*transform)(void *), void *opaque);

#endif
