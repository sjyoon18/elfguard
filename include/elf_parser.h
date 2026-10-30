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

typedef struct {
    uint32_t type;
    uint32_t flags;
    uint64_t file_offset;
    uint64_t virtual_address;
    uint64_t physical_address;
    uint64_t file_size;
    uint64_t memory_size;
    uint64_t alignment;
} Elf64ProgramHeader;

typedef struct {
    uint32_t name_offset;
    uint32_t type;
    uint64_t flags;
    uint64_t address;
    uint64_t file_offset;
    uint64_t size;
    uint32_t link;
    uint32_t info;
    uint64_t alignment;
    uint64_t entry_size;
} Elf64SectionHeader;

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

typedef enum {
    ELF_PROGRAM_HEADER_OK = 0,
    ELF_PROGRAM_HEADER_FILE_RANGE_OUT_OF_BOUNDS,
    ELF_PROGRAM_HEADER_MEMORY_SIZE_TOO_SMALL,
    ELF_PROGRAM_HEADER_INVALID_ALIGNMENT,
    ELF_PROGRAM_HEADER_ALIGNMENT_MISMATCH
} ElfProgramHeaderStatus;

typedef enum {
    ELF_SECTION_HEADER_OK = 0,
    ELF_SECTION_HEADER_FILE_RANGE_OUT_OF_BOUNDS,
    ELF_SECTION_HEADER_INVALID_ALIGNMENT,
    ELF_SECTION_HEADER_ADDRESS_ALIGNMENT_MISMATCH,
    ELF_SECTION_HEADER_SIZE_NOT_MULTIPLE_OF_ENTRY_SIZE
} ElfSectionHeaderStatus;

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

bool elf_decode_program_header(
    const ByteView *view,
    const Elf64Header *header,
    uint16_t index,
    Elf64ProgramHeader *result
);

ElfProgramHeaderStatus elf_validate_program_header(
    const ByteView *view,
    const Elf64ProgramHeader *program_header
);

bool elf_program_header_is_writable_executable(
    const Elf64ProgramHeader *program_header
);

bool elf_decode_section_header(
    const ByteView *view,
    const Elf64Header *header,
    uint16_t index,
    Elf64SectionHeader *result
);

ElfSectionHeaderStatus elf_validate_section_header(
    const ByteView *view,
    const Elf64SectionHeader *section_header
);

#endif
