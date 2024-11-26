#include <ssl/mp.h>
#include <ft/string.h>

void mp_init(u8 *string, size_t size)
{
	ft_memset(string, 0, size);
}

bool mp_add(u8 *string, size_t size, size_t amount)
{
	bool carry = false;

	for (size_t i = 0; i < size && (carry || amount); i++) {
		u16 tmp = string[i] + amount + carry;

		carry = tmp & 0xff00;
		string[i] = tmp & 0x00ff;

		amount >>= 8;
	}

	return amount || carry;
}

bool mp_sub(u8 *string, size_t size, size_t amount)
{
	bool carry = false;

	for (size_t i = 0; i < size && (carry || amount); i++) {
		u8 tmp = string[i] - (u8) amount - carry;

		carry = (amount & 0xff) > (string[i] & 0xff);
		string[i] = tmp;

		amount >>= 8;
	}
	return amount || carry;
}

static void swap_bytes(u8 *a, u8 *b)
{
	u8 tmp = *a;

	*a = *b;
	*b = tmp;
}

static void mp_swap_bytes(u8 *string, size_t size)
{
	size_t halfsize = size / 2;

	for (size_t i = 0; i < halfsize; i += 1)  {
		swap_bytes(&string[i], &string[size - 1 - i]);
	}
}

void mp_encode(u8 *string, size_t size, enum endian endian)
{
	switch (endian) {
	case ENDIAN_LITTLE:
		break;
	case ENDIAN_BIG:
		mp_swap_bytes(string, size);
		break;
	}
}
