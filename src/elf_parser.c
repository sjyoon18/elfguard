#include "elf_parser.h"

enum {
    ELF_IDENT_SIZE = 16,

    ELF_EI_MAG0 = 0,
    ELF_EI_MAG1 = 1,
    ELF_EI_MAG2 = 2,
    ELF_EI_MAG3 = 3,
    ELF_EI_CLASS = 4,
    ELF_EI_DATA = 5,
    ELF_EI_VERSION = 6,

    ELF_CLASS_64 = 2,
    ELF_DATA_LITTLE_ENDIAN = 1,
    ELF_VERSION_CURRENT = 1
};

ElfIdentStatus elf_validate_identification(const ByteView *view) {
    if (!byte_view_contains(view, 0, ELF_IDENT_SIZE)) {
        return ELF_IDENT_TRUNCATED;
    }

    if (view->data[ELF_EI_MAG0] != 0x7f ||
        view->data[ELF_EI_MAG1] != 'E' ||
        view->data[ELF_EI_MAG2] != 'L' ||
        view->data[ELF_EI_MAG3] != 'F'
        ) {
            return ELF_IDENT_BAD_MAGIC;
        }
    
    if (view->data[ELF_EI_CLASS] != ELF_CLASS_64) {
        return ELF_IDENT_UNSUPPORTED_CLASS;
    }

    if (view->data[ELF_EI_DATA] != ELF_DATA_LITTLE_ENDIAN) {
        return ELF_IDENT_UNSUPPORTED_ENCODING;
    }

    if (view->data[ELF_EI_VERSION] != ELF_VERSION_CURRENT) {
        return ELF_IDENT_UNSUPPORTED_VERSION;
    }

    return ELF_IDENT_OK;
}
