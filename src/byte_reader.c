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
