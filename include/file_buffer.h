#ifndef FILE_BUFFER_H
#define FILE_BUFFER_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    size_t size;
} FileBuffer;

int file_buffer_load(const char *path, FileBuffer *buffer);

void file_buffer_destroy(FileBuffer *buffer);

#endif
