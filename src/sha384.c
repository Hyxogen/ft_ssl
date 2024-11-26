#include <ssl/digest/sha2.h>
#include <ft/string.h>

void sha384_init(struct sha384_ctx *ctx)
{
	sha512_init(&ctx->inner);

	ctx->inner.hash.words[0] = 0xcbbb9d5dc1059ed8;
	ctx->inner.hash.words[1] = 0x629a292a367cd507;
	ctx->inner.hash.words[2] = 0x9159015a3070dd17;
	ctx->inner.hash.words[3] = 0x152fecd8f70e5939;
	ctx->inner.hash.words[4] = 0x67332667ffc00b31;
	ctx->inner.hash.words[5] = 0x8eb44a8768581511;
	ctx->inner.hash.words[6] = 0xdb0c2e0d64f98fa7;
	ctx->inner.hash.words[7] = 0x47b5481dbefa4fa4;
}

size_t sha384_update(struct sha384_ctx *ctx, const void *buf, size_t n)
{
	return sha512_update(&ctx->inner, buf, n);
}

void sha384_final(struct sha384_ctx *ctx, unsigned char *dest)
{
	unsigned char buf[SHA512_DIGEST_LEN];

	sha512_final(&ctx->inner, buf);
	ft_memcpy(dest, buf, SHA384_DIGEST_LEN);
}
