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
    ELF_SECTION_NAME_INDEX_EXTENDED = 0xffff,

    ELF_PH_TYPE = 0,
    ELF_PH_FLAGS = 4,
    ELF_PH_OFFSET = 8,
    ELF_PH_VADDR = 16,
    ELF_PH_PADDR = 24,
    ELF_PH_FILESZ = 32,
    ELF_PH_MEMSZ = 40,
    ELF_PH_ALIGN = 48,

    ELF_PROGRAM_TYPE_NULL = 0,
    ELF_PROGRAM_TYPE_LOAD = 1,

    ELF_PROGRAM_FLAG_EXECUTE = 1,
    ELF_PROGRAM_FLAG_WRITE = 2,
    ELF_PROGRAM_FLAG_READ = 4,

    ELF_SH_NAME = 0,
    ELF_SH_TYPE = 4,
    ELF_SH_FLAGS = 8,
    ELF_SH_ADDR = 16,
    ELF_SH_OFFSET = 24,
    ELF_SH_SIZE = 32,
    ELF_SH_LINK = 40,
    ELF_SH_INFO = 44,
    ELF_SH_ADDRALIGN = 48,
    ELF_SH_ENTSIZE = 56,

    ELF_SECTION_TYPE_NULL = 0,
    ELF_SECTION_TYPE_NOBITS = 8
};

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

static bool file_range_fits(
    const ByteView *view,
    uint64_t offset,
    uint64_t length
) {
    if ((uintmax_t)offset > (uintmax_t)view->size) {
        return false;
    }

    uintmax_t remaining =
        (uintmax_t)view->size - (uintmax_t)offset;

    return (uintmax_t)length <= remaining;
}

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

bool elf_decode_program_header(
    const ByteView *view,
    const Elf64Header *header,
    uint16_t index,
    Elf64ProgramHeader *result
) {
    if (header->program_header_entry_size !=
        ELF_PROGRAM_HEADER_SIZE) {
        return false;
    }

    if (index >= header->program_header_count) {
        return false;
    }

    if (!table_fits(
        view,
        header->program_header_offset,
        header->program_header_entry_size,
        header->program_header_count
    )) {
        return false;
    }

    uintmax_t entry_offset_value =
        (uintmax_t)header->program_header_offset +
        (uintmax_t)index * ELF_PROGRAM_HEADER_SIZE;
    
    size_t entry_offset = (size_t)entry_offset_value;

    Elf64ProgramHeader decoded = {0};

    if (!byte_view_read_u32_le(
            view,
            entry_offset + ELF_PH_TYPE,
            &decoded.type
        ) ||
        !byte_view_read_u32_le(
            view,
            entry_offset + ELF_PH_FLAGS,
            &decoded.flags
        )) {
        return false;
    }
    
    if (!byte_view_read_u64_le(
            view,
            entry_offset + ELF_PH_OFFSET,
            &decoded.file_offset
        ) ||
        !byte_view_read_u64_le(
            view,
            entry_offset + ELF_PH_VADDR,
            &decoded.virtual_address
        ) ||
        !byte_view_read_u64_le(
            view,
            entry_offset + ELF_PH_PADDR,
            &decoded.physical_address
        )) {
        return false;
    }
    
    if (!byte_view_read_u64_le(
            view,
            entry_offset + ELF_PH_FILESZ,
            &decoded.file_size
        ) ||
        !byte_view_read_u64_le(
            view,
            entry_offset + ELF_PH_MEMSZ,
            &decoded.memory_size
        ) ||
        !byte_view_read_u64_le(
            view,
            entry_offset + ELF_PH_ALIGN,
            &decoded.alignment
        )) {
        return false;
    }
    
    *result = decoded;
    return true;
}

ElfProgramHeaderStatus elf_validate_program_header(
    const ByteView *view,
    const Elf64ProgramHeader *program_header
) {
    if (program_header->type == ELF_PROGRAM_TYPE_NULL) {
        return ELF_PROGRAM_HEADER_OK;
    }
    if (!file_range_fits(
            view,
            program_header->file_offset,
            program_header->file_size
    )) {
        return ELF_PROGRAM_HEADER_FILE_RANGE_OUT_OF_BOUNDS;
    }

    if (program_header->type == ELF_PROGRAM_TYPE_LOAD &&
        program_header->memory_size < program_header->file_size) {
            return ELF_PROGRAM_HEADER_MEMORY_SIZE_TOO_SMALL;
    }

    if (program_header->alignment <= 1) {
        return ELF_PROGRAM_HEADER_OK;
    }

    if ((program_header->alignment & (program_header->alignment - 1)) != 0) {
        return ELF_PROGRAM_HEADER_INVALID_ALIGNMENT;
    }

    if (program_header->file_offset % program_header->alignment !=
        program_header->virtual_address % program_header->alignment) {
        return ELF_PROGRAM_HEADER_ALIGNMENT_MISMATCH;
    }

    return ELF_PROGRAM_HEADER_OK;
}

bool elf_program_header_is_writable_executable(
    const Elf64ProgramHeader *program_header
) {
    if (program_header->type == ELF_PROGRAM_TYPE_NULL) {
        return false;
    }

    bool writable =
        (program_header->flags & ELF_PROGRAM_FLAG_WRITE) != 0;
    bool executable = 
        (program_header->flags & ELF_PROGRAM_FLAG_EXECUTE) != 0;
    
    return writable && executable;
}

bool elf_decode_section_header(
    const ByteView *view,
    const Elf64Header *header,
    uint16_t index,
    Elf64SectionHeader *result
) {
    if (header->section_header_entry_size !=
        ELF_SECTION_HEADER_SIZE) {
            return false;
    }

    if (index >= header->section_header_count) {
        return false;
    }

    if (!table_fits(
        view,
        header->section_header_offset,
        header->section_header_entry_size,
        header->section_header_count
    )) {
        return false;
    }

    uintmax_t entry_offset_value =
        (uintmax_t)header->section_header_offset +
        (uintmax_t)index * ELF_SECTION_HEADER_SIZE;
    
    size_t entry_offset = (size_t)entry_offset_value;

    Elf64SectionHeader decoded = {0};

    if (!byte_view_read_u32_le(
            view,
            entry_offset + ELF_SH_NAME,
            &decoded.name_offset
        ) ||
        !byte_view_read_u32_le(
            view,
            entry_offset + ELF_SH_TYPE,
            &decoded.type
        ) ||
        !byte_view_read_u64_le(
            view,
            entry_offset + ELF_SH_FLAGS,
            &decoded.flags
        )) {
        return false;
    }

    if (!byte_view_read_u64_le(
            view,
            entry_offset + ELF_SH_ADDR,
            &decoded.address
        ) ||
        !byte_view_read_u64_le(
            view,
            entry_offset + ELF_SH_OFFSET,
            &decoded.file_offset
        ) ||
        !byte_view_read_u64_le(
            view,
            entry_offset + ELF_SH_SIZE,
            &decoded.size
        )) {
        return false;
    }

    if (!byte_view_read_u32_le(
            view,
            entry_offset + ELF_SH_LINK,
            &decoded.link
        ) ||
        !byte_view_read_u32_le(
            view,
            entry_offset + ELF_SH_INFO,
            &decoded.info
        ) ||
        !byte_view_read_u64_le(
            view,
            entry_offset + ELF_SH_ADDRALIGN,
            &decoded.alignment
        ) ||
        !byte_view_read_u64_le(
            view,
            entry_offset + ELF_SH_ENTSIZE,
            &decoded.entry_size
        )) {
        return false;
    }

    *result = decoded;
    return true;
}

ElfSectionHeaderStatus elf_validate_section_header(
    const ByteView *view,
    const Elf64SectionHeader *section_header
) {
    if (section_header->type == ELF_SECTION_TYPE_NULL) {
        return ELF_SECTION_HEADER_OK;
    }
    
    if (section_header->type != ELF_SECTION_TYPE_NOBITS &&
        !file_range_fits(
            view,
            section_header->file_offset,
            section_header->size
        )) {
        return ELF_SECTION_HEADER_FILE_RANGE_OUT_OF_BOUNDS;
    }

    if (section_header->alignment > 1) {
        if ((section_header->alignment &
            (section_header->alignment - 1)) != 0) {
            return ELF_SECTION_HEADER_INVALID_ALIGNMENT;
        }

        if (section_header->address %
            section_header->alignment != 0) {
            return ELF_SECTION_HEADER_ADDRESS_ALIGNMENT_MISMATCH;
        }
    }

    if (section_header->entry_size != 0 &&
        section_header->size % section_header->entry_size != 0) {
        return ELF_SECTION_HEADER_SIZE_NOT_MULTIPLE_OF_ENTRY_SIZE;
    }

    return ELF_SECTION_HEADER_OK;
}
