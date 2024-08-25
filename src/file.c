#include <ssl/file.h>

#include <unistd.h>

ssize_t file_read(struct file *file, void *buf, size_t count)
{
	if (file->type == FILE_TYPE_FD)
		return read(file->data.fd, buf, count);

	unsigned char *buf_c = buf;
	size_t i = 0;

	for (; i < count && *file->data.str; ++i) {
		*buf_c++ = *(const unsigned char *)file->data.str++;
	}
	return i;
}
