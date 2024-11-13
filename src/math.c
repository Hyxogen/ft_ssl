#include <ssl/math.h>
#include <assert.h>

/* TODO write tests */
//https://blog.regehr.org/archives/1063
u32 ssl_rotleft32(u32 val, u8 amount)
{
	assert(amount < 32);
	return (val << amount) | (val >> (-amount&31));
}

u32 ssl_rotright32(u32 val, u8 amount)
{
	assert(amount < 32);
	return (val >> amount) | (val << (-amount&31));
}

u64 ssl_rotleft64(u64 val, u8 amount)
{
	assert(amount < 64);
	return (val << amount) | (val >> (-amount&63));
}

u64 ssl_rotright64(u64 val, u8 amount)
{
	assert(amount < 64);
	return (val >> amount) | (val << (-amount&63));
}
