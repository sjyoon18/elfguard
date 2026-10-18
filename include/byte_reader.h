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

bool byte_view_read_u8(
    const ByteView *view,
    size_t offset,
    uint8_t *result
);

bool byte_view_read_u16_le(
    const ByteView *view,
    size_t offset,
    uint16_t *result
);

bool byte_view_read_u32_le(
    const ByteView *view,
    size_t offset,
    uint32_t *result
);

bool byte_view_read_u64_le(
    const ByteView *view,
    size_t offset,
    uint64_t *result
);

#endif
