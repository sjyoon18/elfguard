#include "byte_reader.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    uint8_t bytes[8] = {0};

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

    printf("All byte reader range tests passed.\n");
    return 0;
}
