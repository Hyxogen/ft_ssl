#ifndef SSL_MATH_H
#define SSL_MATH_H

#include <ssl/types.h>

u32 ssl_rotleft32(u32 val, u8 amount);
u32 ssl_rotright32(u32 val, u8 amount);

u64 ssl_rotleft64(u64 val, u8 amount);
u64 ssl_rotright64(u64 val, u8 amount);

#endif
