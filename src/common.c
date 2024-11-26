#include <ssl/digest/common.h>
#include <ft/string.h>
#include <ssl/mp.h>
#include <limits.h>

static const u8 dgst_padding[256] = { 0x80 };

static size_t dgst_generic_fill(u8 *block, size_t block_size, size_t offset,
				const u8 *data, size_t n)
{
	size_t rem = block_size - offset;

	if (rem < n)
		n = rem;

	ft_memcpy(&block[offset], data, n);

	return n;
}

void dgst_generic_update(u8 *block, size_t block_size, size_t *offset,
			 const u8 *data, size_t nbytes,
			 void (*transform)(void *), void *opaque)
{
	size_t nwritten = 0;

	while (nwritten < nbytes) {
		size_t n =
		    dgst_generic_fill(block, block_size, *offset,
				      data + nwritten, nbytes - nwritten);

		*offset = (*offset + n) % block_size;
		nwritten += n;

		if (!*offset)
			transform(opaque);
	}
}

void dgst_generic_pad(u8 *block, size_t block_size, u8 *mp_length,
		      size_t mp_size, size_t offset, enum endian endian,
		      void (*transform)(void *), void *opaque)
{
	size_t padding = 1; /* 1 for the 0x80 byte */

	size_t saved = offset;
	offset = (offset + 1) % block_size;

	size_t stop = block_size - mp_size;
	if (offset > stop) {
		padding += block_size - offset;
		padding += stop;
	} else {
		padding += stop - offset;
	}

	offset = saved;

	dgst_generic_update(block, block_size, &offset, dgst_padding, padding, transform, opaque);

	mp_encode(mp_length, mp_size, endian);
	dgst_generic_update(block, block_size, &offset, mp_length, mp_size, transform, opaque);
}
