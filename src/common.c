#include <ssl/digest/common.h>
#include <ft/string.h>

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
		    dgst_generic_fill(block, block_size, *offset, data, nbytes);

		*offset = (*offset + n) % block_size;
		nwritten += n;

		if (!*offset)
			transform(opaque);
	}
}

