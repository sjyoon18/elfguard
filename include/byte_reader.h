#ifndef BYTE_READER_H
#define BYTE_READER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const uint8_t *data;
    size_t size;
} ByteView;

bool byte_view_contains(
    const ByteView *view,
    size_t offset,
    size_t length
);

#endif
