#include "file_buffer.h"

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#define MAX_FILE_SIZE (64ULL * 1024ULL * 1024ULL)

static int read_all(int fd, uint8_t *data, size_t size) {
    size_t total_read = 0;

    while (total_read < size) {
        ssize_t bytes_read = read(
            fd,
            data + total_read,
            size - total_read
        );

        if (bytes_read == -1) {
            if (errno == EINTR) {
                continue;
            }

            return -1;
        }

        if (bytes_read == 0) {
            errno = EIO;
            return -1;
        }

        total_read += (size_t)bytes_read;
    }

    return 0;
}

int file_buffer_load(const char *path, FileBuffer *buffer) {
    int fd = open(path, O_RDONLY | O_NONBLOCK);

    if (fd == -1) {
        return -1;
    }

    struct stat information;

    if (fstat(fd, &information) == -1) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    if (!S_ISREG(information.st_mode)) {
        close(fd);
        errno = EINVAL;
        return -1;
    }

    if (information.st_size < 0) {
        close(fd);
        errno = EINVAL;
        return -1;
    }

    if ((uintmax_t)information.st_size > (uintmax_t)SIZE_MAX ||
        (uintmax_t)information.st_size > MAX_FILE_SIZE) {
        close(fd);
        errno = EFBIG;
        return -1;
    }

    size_t size = (size_t)information.st_size;

    if (size == 0) {
        if (close(fd) == -1) {
            return -1;
        }

        return 0;
    }

    uint8_t *data = malloc(size);

    if (data == NULL) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    if (read_all(fd, data, size) < 0) {
        int saved_errno = errno;
        free(data);
        close(fd);
        errno = saved_errno;
        return -1;
    }

    if (close(fd) == -1) {
        int saved_errno = errno;
        free(data);
        errno = saved_errno;
        return -1;
    }

    buffer->data = data;
    buffer->size = size;

    return 0;
}

void file_buffer_destroy(FileBuffer *buffer) {
    free(buffer->data);
    buffer->data = NULL;
    buffer->size = 0;
}
