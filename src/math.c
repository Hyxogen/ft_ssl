#include <ssl/math.h>
#include <assert.h>

u32 ssl_rotleft32(u32 val, u8 amount)
{
	assert(amount < 32);
	if (!amount)
		return val;
	return (val << amount) | (val >> (32 - amount));
}
