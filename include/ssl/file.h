#ifndef FT_SSL_FILE_H
#define FT_SSL_FILE_H

#include <stddef.h>
#include <sys/types.h>

#define FILE_TYPE_STRING 0x1
#define FILE_TYPE_FD 0x2

struct file {
	int type;
	union {
		const char *str;
		int fd;
	} data;
};

void file_from_str(struct file *file, const char *str);
void file_from_fd(struct file, int fd);
ssize_t file_read(struct file *file, void *buf, size_t count);

#endif
