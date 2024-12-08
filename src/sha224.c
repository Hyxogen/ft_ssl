#include <ssl/digest/sha2.h>
#include <ft/string.h>

void sha224_init(struct sha224_ctx *ctx)
{
	sha256_init(&ctx->inner);

	ctx->inner.state[0] = 0xc1059ed8;
	ctx->inner.state[1] = 0x367cd507;
	ctx->inner.state[2] = 0x3070dd17;
	ctx->inner.state[3] = 0xf70e5939;
	ctx->inner.state[4] = 0xffc00b31;
	ctx->inner.state[5] = 0x68581511;
	ctx->inner.state[6] = 0x64f98fa7;
	ctx->inner.state[7] = 0xbefa4fa4;
}

void sha224_update(struct sha224_ctx *ctx, const void *buf, size_t n)
{
	sha256_update(&ctx->inner, buf, n);
}

void sha224_final(unsigned char dest[SHA224_DIGEST_LEN], struct sha224_ctx *ctx)
{
	unsigned char buf[SHA256_DIGEST_LEN];
	sha256_final(buf, &ctx->inner);
	ft_memcpy(dest, buf, SHA224_DIGEST_LEN);
}
