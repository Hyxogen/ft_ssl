#include <ssl/md5.h>
#include <unistd.h>
#include <stdio.h>

int main(void)
{
	char buf[64];

	struct md5_ctx ctx;
	md5_init(&ctx);

	while (1) {
		ssize_t nread = read(0, buf, sizeof(buf));

		if (nread < 0) {
			perror("read");
			return -1;
		}

		if (!nread) {
			break;
		}
		size_t nwritten = 0;

		while (nwritten < (size_t) nread)
			nwritten += md5_write(&ctx, buf + nwritten, nread - nwritten);
	}

	unsigned char res[16];

	md5_finalize(&ctx, res);

	for (unsigned i = 0; i < sizeof(res); i++) {
		printf("%02hhx", res[i]);
	}
	printf("\n");
	return 0;
}
