#include "elf_parser.h"

enum {
    ELF_IDENT_SIZE = 16,
    ELF_HEADER_SIZE = 64,
    
    ELF_EI_MAG0 = 0,
    ELF_EI_MAG1 = 1,
    ELF_EI_MAG2 = 2,
    ELF_EI_MAG3 = 3,
    ELF_EI_CLASS = 4,
    ELF_EI_DATA = 5,
    ELF_EI_VERSION = 6,

    ELF_E_TYPE = 16,
    ELF_E_MACHINE = 18,
    ELF_E_VERSION = 20,
    ELF_E_ENTRY = 24,
    ELF_E_PHOFF = 32,
    ELF_E_SHOFF = 40,
    ELF_E_FLAGS = 48,
    ELF_E_EHSIZE = 52,
    ELF_E_PHENTSIZE = 54,
    ELF_E_PHNUM = 56,
    ELF_E_SHENTSIZE = 58,
    ELF_E_SHNUM = 60,
    ELF_E_SHSTRNDX = 62,

    ELF_CLASS_64 = 2,
    ELF_DATA_LITTLE_ENDIAN = 1,
    ELF_VERSION_CURRENT = 1,

    ELF_TYPE_RELOCATABLE = 1,
    ELF_TYPE_EXECUTABLE = 2,
    ELF_TYPE_SHARED_OBJECT = 3,

    ELF_MACHINE_X86_64 = 62,
    ELF_HEADER_VERSION_CURRENT = 1,

    ELF_PROGRAM_HEADER_SIZE = 56,
    ELF_PROGRAM_HEADER_EXTENDED_COUNT = 0xffff,

    ELF_SECTION_HEADER_SIZE = 64,
    ELF_SECTION_NAME_INDEX_EXTENDED = 0xffff    
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

bool elf_decode_header(
    const ByteView *view,
    Elf64Header *result
) {
    if (!byte_view_contains(view, 0, ELF_HEADER_SIZE)) {
        return false;
    }

    Elf64Header decoded = {0};

    if (!byte_view_read_u16_le(
            view,
            ELF_E_TYPE,
            &decoded.type
        ) ||
        !byte_view_read_u16_le(
            view,
            ELF_E_MACHINE,
            &decoded.machine
        ) ||
        !byte_view_read_u32_le(
            view,
            ELF_E_VERSION,
            &decoded.version
        )) {
        return false;
    }

    if (!byte_view_read_u64_le(
            view,
            ELF_E_ENTRY,
            &decoded.entry
        ) ||
        !byte_view_read_u64_le(
            view,
            ELF_E_PHOFF,
            &decoded.program_header_offset
        ) ||
        !byte_view_read_u64_le(
            view,
            ELF_E_SHOFF,
            &decoded.section_header_offset
        ) ||
        !byte_view_read_u32_le(
            view,
            ELF_E_FLAGS,
            &decoded.flags
        )) {
        return false;
    }

    if (!byte_view_read_u16_le(
            view,
            ELF_E_EHSIZE,
            &decoded.header_size
        ) ||
        !byte_view_read_u16_le(
            view,
            ELF_E_PHENTSIZE,
            &decoded.program_header_entry_size
        ) ||
        !byte_view_read_u16_le(
            view,
            ELF_E_PHNUM,
            &decoded.program_header_count
        ) ||
        !byte_view_read_u16_le(
            view,
            ELF_E_SHENTSIZE,
            &decoded.section_header_entry_size
        ) ||
        !byte_view_read_u16_le(
            view,
            ELF_E_SHNUM,
            &decoded.section_header_count
        ) ||
        !byte_view_read_u16_le(
            view,
            ELF_E_SHSTRNDX,
            &decoded.section_name_table_index
        )) {
        return false;
    }

    *result = decoded;
    return true;
}

ElfHeaderStatus elf_validate_header(const Elf64Header *header) {
    if (header->type != ELF_TYPE_RELOCATABLE &&
        header->type != ELF_TYPE_EXECUTABLE &&
        header->type != ELF_TYPE_SHARED_OBJECT) {
            return ELF_HEADER_UNSUPPORTED_TYPE;
        }
    
    if (header->machine != ELF_MACHINE_X86_64) {
        return ELF_HEADER_UNSUPPORTED_MACHINE;
    }

    if (header->version != ELF_HEADER_VERSION_CURRENT) {
        return ELF_HEADER_UNSUPPORTED_VERSION;
    }

    if (header->header_size != ELF_HEADER_SIZE) {
        return ELF_HEADER_INVALID_SIZE;
    }

    return ELF_HEADER_OK;
}

static bool table_fits(
    const ByteView *view,
    uint64_t offset,
    uint16_t entry_size,
    uint16_t entry_count
) {
    if (entry_count == 0) {
        return true;
    }

    if (entry_size == 0) {
        return false;
    }

    if ((uintmax_t)offset > (uintmax_t)view->size) {
        return false;
    }

    uintmax_t remaining_bytes = (uintmax_t)view->size - (uintmax_t)offset;

    return (uintmax_t)entry_count <= remaining_bytes / (uintmax_t)entry_size;
}

ElfLayoutStatus elf_validate_layout(
    const ByteView *view,
    const Elf64Header *header
) {
    if (header->program_header_count != 0) {
        if (header->program_header_offset == 0) {
            return ELF_LAYOUT_INVALID_PROGRAM_HEADER_OFFSET;
        }

        if (header->program_header_count == ELF_PROGRAM_HEADER_EXTENDED_COUNT) {
            return ELF_LAYOUT_UNSUPPORTED_EXTENDED_NUMBERING;
        }

        if (header->program_header_entry_size != ELF_PROGRAM_HEADER_SIZE) {
            return ELF_LAYOUT_INVALID_PROGRAM_HEADER_ENTRY_SIZE;
        }

        if (!table_fits(
                view,
                header->program_header_offset,
                header->program_header_entry_size,
                header->program_header_count
                )) {
                return ELF_LAYOUT_PROGRAM_HEADER_TABLE_OUT_OF_BOUNDS;
            }
    }

    if (header->section_header_count == 0) {
            if (header->section_header_offset != 0) {
                return ELF_LAYOUT_UNSUPPORTED_EXTENDED_NUMBERING;
            }

            if (header->section_name_table_index != 0) {
                return ELF_LAYOUT_INVALID_SECTION_NAME_TABLE_INDEX;
            }
        } else {
            if (header->section_name_table_index ==
                ELF_SECTION_NAME_INDEX_EXTENDED) {
                return ELF_LAYOUT_UNSUPPORTED_EXTENDED_NUMBERING;
            }

            if (header->section_header_offset == 0) {
                return ELF_LAYOUT_INVALID_SECTION_HEADER_OFFSET;
            }

            if (header->section_header_entry_size !=
                ELF_SECTION_HEADER_SIZE) {
                return ELF_LAYOUT_INVALID_SECTION_HEADER_ENTRY_SIZE;
            }

            if (!table_fits(
                    view,
                    header->section_header_offset,
                    header->section_header_entry_size,
                    header->section_header_count
                )) {
                return ELF_LAYOUT_SECTION_HEADER_TABLE_OUT_OF_BOUNDS;
            }

            if (header->section_name_table_index != 0 &&
                header->section_name_table_index >=
                header->section_header_count) {
                return ELF_LAYOUT_INVALID_SECTION_NAME_TABLE_INDEX;
            }
        }

    return ELF_LAYOUT_OK;
}
