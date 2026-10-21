#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include "byte_reader.h"

typedef enum {
    ELF_IDENT_OK = 0,
    ELF_IDENT_TRUNCATED,
    ELF_IDENT_BAD_MAGIC,
    ELF_IDENT_UNSUPPORTED_CLASS,
    ELF_IDENT_UNSUPPORTED_ENCODING,
    ELF_IDENT_UNSUPPORTED_VERSION
} ElfIdentStatus;

typedef struct {
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint64_t entry;
    uint64_t program_header_offset;
    uint64_t section_header_offset;
    uint32_t flags;
    uint16_t header_size;
    uint16_t program_header_entry_size;
    uint16_t program_header_count;
    uint16_t section_header_entry_size;
    uint16_t section_header_count;
    uint16_t section_name_table_index;
} Elf64Header;

typedef enum {
    ELF_HEADER_OK = 0,
    ELF_HEADER_UNSUPPORTED_TYPE,
    ELF_HEADER_UNSUPPORTED_MACHINE,
    ELF_HEADER_UNSUPPORTED_VERSION,
    ELF_HEADER_INVALID_SIZE
} ElfHeaderStatus;

typedef enum {
    ELF_LAYOUT_OK = 0,

    ELF_LAYOUT_UNSUPPORTED_EXTENDED_NUMBERING,

    ELF_LAYOUT_INVALID_PROGRAM_HEADER_OFFSET,
    ELF_LAYOUT_INVALID_PROGRAM_HEADER_ENTRY_SIZE,
    ELF_LAYOUT_PROGRAM_HEADER_TABLE_OUT_OF_BOUNDS,

    ELF_LAYOUT_INVALID_SECTION_HEADER_OFFSET,
    ELF_LAYOUT_INVALID_SECTION_HEADER_ENTRY_SIZE,
    ELF_LAYOUT_SECTION_HEADER_TABLE_OUT_OF_BOUNDS,
    
    ELF_LAYOUT_INVALID_SECTION_NAME_TABLE_INDEX
} ElfLayoutStatus;

ElfIdentStatus elf_validate_identification(const ByteView *view);

bool elf_decode_header(
    const ByteView *view,
    Elf64Header *result
);

ElfHeaderStatus elf_validate_header(const Elf64Header *header);

ElfLayoutStatus elf_validate_layout(
    const ByteView *view,
    const Elf64Header *header
);

#endif
