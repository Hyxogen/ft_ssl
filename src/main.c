#include <ssl/digest/md4.h>
#include <ssl/digest/md5.h>
#include <ssl/digest/sha1.h>
#include <ssl/digest/sha2.h>
#include <ssl/digest/sha3.h>
#include <ssl/digest/whirlpool.h>
#include <unistd.h>
#include <stdio.h>
#include <ft/stdio.h>
#include <ft/strings.h>
#include <ft/string.h>
#include <stdlib.h>
#include <errno.h>

static int exec_digest(int argc, char **argv);
static int do_aes(int argc, char **argv);
static int print_help(int argc, char **argv);

struct digest {
	const char *name;
	size_t digest_len;

	void* (*create)(void);
	void (*free)(void*);

	void (*update)(void *, const void *buf, size_t n);
	void (*final)(void *, u8 *dest);
};

#define SSL_DIGESTS               \
	X(md4, "md4")             \
	X(md5, "md5")             \
	X(whirlpool, "whirlpool") \
	X(sha1, "sha1")           \
	X(sha224, "sha224")       \
	X(sha256, "sha256")       \
	X(sha384, "sha384")       \
	X(sha512, "sha512")       \
	X(sha3_224, "sha3-224")   \
	X(sha3_256, "sha3-256")   \
	X(sha3_384, "sha3-384")   \
	X(sha3_512, "sha3-512")

#define X(name, ident)                                                 \
	static void *digest_##name##_create(void)                      \
	{                                                              \
		struct name##_ctx *ctx = malloc(sizeof(*ctx));         \
		if (ctx) {                                             \
			name##_init(ctx);                              \
		}                                                      \
		return ctx;                                            \
	}                                                              \
                                                                       \
	static void digest_##name##_free(void *ctx)                    \
	{                                                              \
		free(ctx);                                             \
	}                                                              \
                                                                       \
	static void digest_##name##_update(void *ctx, const void *buf, \
					   size_t n)                   \
	{                                                              \
		name##_update(ctx, buf, n);                            \
	}                                                              \
                                                                       \
	static void digest_##name##_final(void *ctx, u8 *dest)         \
	{                                                              \
		name##_final(ctx, dest);                               \
	}

SSL_DIGESTS

#undef X

static const struct digest digests[] = {
#define X(digest_name, ident)                        \
	{                                            \
	    .name = ident,                          \
	    .digest_len = digest_name##_digest_len,  \
	    .create = digest_##digest_name##_create, \
	    .free = digest_##digest_name##_free,     \
	    .update = digest_##digest_name##_update, \
	    .final = digest_##digest_name##_final,   \
	},
    SSL_DIGESTS
#undef X
    {.name = NULL},
};

static const struct command {
	const char *cmd;

	int (*exec)(int argc, char **argv);
} commands[] = {
#define X(digest_name, ident) {ident, exec_digest},
    SSL_DIGESTS
#undef X
    {"aes", do_aes},
    {NULL, NULL},
};

static const struct digest *find_digest(const char *name)
{
	for (unsigned i = 0; digests[i].name; i++) {
		if (!ft_strcmp(digests[i].name, name))
			return &digests[i];
	}
	return NULL;
}

static int do_digest(u8 *dest, const struct digest *d, void *ctx)
{
	char buf[1024];

	while (1) {
		ssize_t nread = read(0, buf, sizeof(buf));

		if (nread < 0) {
			perror("read");
			return -errno;
		}

		if (!nread)
			break;

		d->update(ctx, buf, nread);
	}

	d->final(ctx, dest);
	return 0;
}

static int exec_digest(int argc, char **argv)
{
	if (argc < 1)
		return -EINVAL;

	const struct digest *d = find_digest(argv[0]);
	if (!d)
		return -ENOENT;

	void *ctx = d->create();
	u8 *res = malloc(d->digest_len);
	int rc = -ENOMEM;

	if (ctx && res) {
		rc = do_digest(res, d, ctx);

		if (!rc) {
			printf("%s(stdin)= ", d->name);
			for (size_t i = 0; i < d->digest_len; i++) {
				printf("%02hhx", res[i]);
			}
			printf("\n");
		}
	}
	d->free(ctx);
	free(res);
	return rc;
}

void do_chipher(u8 block[16], const u8 key[16], u8 rounds);
static int do_aes(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	u8 input[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
			0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	const u8 key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

	do_chipher(input, key, 10);
	return 0;
}

static int print_help(int argc, char **argv)
{
	(void) argc;
	(void) argv;
	ft_printf("help:\n\n");

	ft_printf("Message digest commands:\n");

	for (int i = 0; commands[i].cmd; i++) {
		printf("%s\n", commands[i].cmd);
	}
	printf("\n");

	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return print_help(argc, argv);

	for (int i = 0; commands[i].cmd; i++) {
		if (!ft_strcasecmp(argv[1], commands[i].cmd))
			return commands[i].exec(argc - 1, argv + 1);
	}

	ft_printf("Invalid command '%s'; type \"help\" for a list\n", argv[1]);

	return EXIT_FAILURE;
}
