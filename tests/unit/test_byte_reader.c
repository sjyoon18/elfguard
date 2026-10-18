#include "byte_reader.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    uint8_t bytes[8] = {
        0x7f, 0x45, 0x4c, 0x46,
        0x02, 0x01, 0x01, 0xaa
    };

    ByteView view = {
        .data = bytes,
        .size = sizeof(bytes)
    };

    assert(byte_view_contains(&view, 0, 8));
    assert(byte_view_contains(&view, 7, 1));
    assert(!byte_view_contains(&view, 7, 2));
    assert(byte_view_contains(&view, 8, 0));
    assert(!byte_view_contains(&view, 9, 0));

    assert(!byte_view_contains(&view, SIZE_MAX, 1));
    assert(!byte_view_contains(&view, 7, SIZE_MAX));


    ByteView empty = {
        .data = NULL,
        .size = 0
    };

    assert(byte_view_contains(&empty, 0, 0));
    assert(!byte_view_contains(&empty, 0, 1));
    assert(!byte_view_contains(&empty, 1, 0));

    uint8_t result = 0;

    assert(byte_view_read_u8(&view, 0, &result));
    assert(result == 0x7f);

    assert(byte_view_read_u8(&view, 7, &result));
    assert(result == 0xaa);

    result = 0xcc;

    assert(!byte_view_read_u8(&view, 8, &result));
    assert(result == 0xcc);

    assert(!byte_view_read_u8(&view, SIZE_MAX, &result));
    assert(result == 0xcc);

    assert(!byte_view_read_u8(&empty, 0, &result));
    assert(result == 0xcc);

    uint16_t result_u16 = 0;

    assert(byte_view_read_u16_le(&view, 0, &result_u16));
    assert(result_u16 == 0x457f);

    assert(byte_view_read_u16_le(&view, 4, &result_u16));
    assert(result_u16 == 0x0102);

    assert(byte_view_read_u16_le(&view, 6, &result_u16));
    assert(result_u16 == 0xaa01);

    result_u16 = 0xcccc;

    assert(!byte_view_read_u16_le(&view, 7, &result_u16));
    assert(result_u16 == 0xcccc);

    assert(!byte_view_read_u16_le(&view, SIZE_MAX, &result_u16));
    assert(result_u16 == 0xcccc);

    assert(!byte_view_read_u16_le(&empty, 0, &result_u16));
    assert(result_u16 == 0xcccc);

    uint32_t result_u32 = 0;

    assert(byte_view_read_u32_le(&view, 0, &result_u32));
    assert(result_u32 == 0x464c457fU);

    assert(byte_view_read_u32_le(&view, 4, &result_u32));
    assert(result_u32 == 0xaa010102U);

    result_u32 = 0xccccccccU;

    assert(!byte_view_read_u32_le(&view, 5, &result_u32));
    assert(result_u32 == 0xccccccccU);

    assert(!byte_view_read_u32_le(&view, SIZE_MAX, &result_u32));
    assert(result_u32 == 0xccccccccU);

    assert(!byte_view_read_u32_le(&empty, 0, &result_u32));
    assert(result_u32 == 0xccccccccU);

    uint64_t result_u64 = 0;

    assert(byte_view_read_u64_le(&view, 0, &result_u64));
    assert(result_u64 == UINT64_C(0xaa010102464c457f));

    result_u64 = UINT64_C(0xcccccccccccccccc);

    assert(!byte_view_read_u64_le(&view, 1, &result_u64));
    assert(result_u64 == UINT64_C(0xcccccccccccccccc));

    assert(!byte_view_read_u64_le(&view, SIZE_MAX, &result_u64));
    assert(result_u64 == UINT64_C(0xcccccccccccccccc));

    assert(!byte_view_read_u64_le(&empty, 0, &result_u64));
    assert(result_u64 == UINT64_C(0xcccccccccccccccc));

    printf("All byte reader tests passed.\n");

    return 0;
}
