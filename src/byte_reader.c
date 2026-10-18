#include "byte_reader.h"

bool byte_view_contains(
    const ByteView *view,
    size_t offset,
    size_t length
) {
    if (offset > view->size) {
        return false;
    }
    if (length > view->size - offset) {
        return false;
    }
    
    return true;
}

bool byte_view_read_u8(
    const ByteView *view,
    size_t offset,
    uint8_t *result
) {
    if (!byte_view_contains(view, offset, sizeof(uint8_t))) {
        return false;
    }

    *result = view->data[offset];

    return true;
}

bool byte_view_read_u16_le(
    const ByteView *view,
    size_t offset,
    uint16_t *result
) {
    if (!byte_view_contains(view, offset, sizeof(uint16_t))) {
        return false;
    }

    uint16_t value =
        (uint16_t)view->data[offset] |
        ((uint16_t)view->data[offset + 1] << 8);

    *result = value;

    return true;
}

bool byte_view_read_u32_le(
    const ByteView *view,
    size_t offset,
    uint32_t *result
) {
    if (!byte_view_contains(view, offset, sizeof(uint32_t))) {
        return false;
    }

    uint32_t value =
        (uint32_t)view->data[offset] |
        ((uint32_t)view->data[offset + 1] << 8) |
        ((uint32_t)view->data[offset + 2] << 16) |
        ((uint32_t)view->data[offset + 3] << 24);

    *result = value;

    return true;
}

bool byte_view_read_u64_le(
    const ByteView *view,
    size_t offset,
    uint64_t *result
) {
    if (!byte_view_contains(view, offset, sizeof(uint64_t))) {
        return false;
    }

    uint64_t value =
        (uint64_t)view->data[offset] |
        ((uint64_t)view->data[offset + 1] << 8) |
        ((uint64_t)view->data[offset + 2] << 16) |
        ((uint64_t)view->data[offset + 3] << 24) |
        ((uint64_t)view->data[offset + 4] << 32) |
        ((uint64_t)view->data[offset + 5] << 40) |
        ((uint64_t)view->data[offset + 6] << 48) |
        ((uint64_t)view->data[offset + 7] << 56);
    
    *result = value;

    return true;
}
