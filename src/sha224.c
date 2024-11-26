#include <ssl/digest/sha2.h>
#include <ft/string.h>

void sha224_init(struct sha224_ctx *ctx)
{
	sha256_init(&ctx->inner);

	ctx->inner.hash.words[0] = 0xc1059ed8;
	ctx->inner.hash.words[1] = 0x367cd507;
	ctx->inner.hash.words[2] = 0x3070dd17;
	ctx->inner.hash.words[3] = 0xf70e5939;
	ctx->inner.hash.words[4] = 0xffc00b31;
	ctx->inner.hash.words[5] = 0x68581511;
	ctx->inner.hash.words[6] = 0x64f98fa7;
	ctx->inner.hash.words[7] = 0xbefa4fa4;
}

void sha224_update(struct sha224_ctx *ctx, const void *buf, size_t n)
{
	sha256_update(&ctx->inner, buf, n);
}

void sha224_final(struct sha224_ctx *ctx, unsigned char *dest)
{
	unsigned char buf[SHA256_DIGEST_LEN];
	sha256_final(&ctx->inner, buf);
	ft_memcpy(dest, buf, SHA224_DIGEST_LEN);
}
