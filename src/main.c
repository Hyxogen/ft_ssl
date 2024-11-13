#include <ssl/md5.h>
#include <ssl/sha2.h>
#include <unistd.h>
#include <stdio.h>
#include <ft/stdio.h>
#include <ft/strings.h>
#include <ft/string.h>
#include <stdlib.h>
#include <errno.h>

static int exec_digest(int argc, char **argv);
static int print_help(int argc, char **argv);

struct digest {
	const char *name;
	size_t digest_len;

	void* (*create)(void);
	void (*free)(void*);

	size_t (*update)(void *, const void *buf, size_t n);
	void (*final)(void *, u8 *dest);
};

#define SSL_DIGESTS \
	X(md5)      \
	X(sha224)   \
	X(sha256)   \
	X(sha384)   \
	X(sha512)

#define X(name)                                                          \
	static void *digest_##name##_create(void)                        \
	{                                                                \
		struct name##_ctx *ctx = malloc(sizeof(*ctx));           \
		if (ctx) {                                               \
			name##_init(ctx);                                \
		}                                                        \
		return ctx;                                              \
	}                                                                \
                                                                         \
	static void digest_##name##_free(void *ctx)                      \
	{                                                                \
		name##_free(ctx);                                        \
		free(ctx);                                               \
	}                                                                \
                                                                         \
	static size_t digest_##name##_update(void *ctx, const void *buf, \
					     size_t n)                   \
	{                                                                \
		return name##_update(ctx, buf, n);                       \
	}                                                                \
                                                                         \
	static void digest_##name##_final(void *ctx, u8 *dest)           \
	{                                                                \
		name##_final(ctx, dest);                                 \
	}

SSL_DIGESTS

#undef X

static const struct digest digests[] = {
#define X(digest_name)                               \
	{                                            \
	    .name = #digest_name,                    \
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
#define X(digest_name) {#digest_name, exec_digest},
SSL_DIGESTS
#undef X
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
	char buf[64];

	while (1) {
		ssize_t nread = read(0, buf, sizeof(buf));

		if (nread < 0) {
			perror("read");
			return -errno;
		}

		if (!nread)
			break;

		size_t nwritten = 0;

		while (nwritten < (size_t) nread)
			nwritten += d->update(ctx, buf + nwritten, nread - nwritten);
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
		
		printf("\n%s(stdin)= ", d->name);
		for (size_t i = 0; i < d->digest_len; i++) {
			printf("%02hhx", res[i]);
		}
	}
	d->free(ctx);
	free(res);
	return rc;
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
