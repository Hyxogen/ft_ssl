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
		u16 tmp = string[i] + (u8) amount + carry;

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

void mp_encode(unsigned char *restrict dest, const u8 *restrict string,
	       size_t size, enum endian endian)
{
	switch (endian) {
	case ENDIAN_LITTLE:
		for (size_t i = 0; i < size; i++) {
			dest[i] = string[i];
		}
		break;
	case ENDIAN_BIG:
		for (size_t i = 0; i < size; i++) {
			dest[size - i - 1] = string[i];
		}
		break;
	}
}
