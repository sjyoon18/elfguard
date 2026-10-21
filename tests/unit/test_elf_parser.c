#include "elf_parser.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

static void test_identification(void) {
    uint8_t identification[16] = {
        0x7f, 'E', 'L', 'F',
        0x02, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    ByteView view = {
        .data = identification,
        .size = sizeof(identification)
    };

    assert(elf_validate_identification(&view) == ELF_IDENT_OK);

    ByteView truncated = {
        .data = identification,
        .size = 15
    };

    assert(
        elf_validate_identification(&truncated) ==
        ELF_IDENT_TRUNCATED
    );

    ByteView empty = {
        .data = NULL,
        .size = 0
    };

    assert(
        elf_validate_identification(&empty) ==
        ELF_IDENT_TRUNCATED
    );

    identification[0] = 0x00;
    assert(
        elf_validate_identification(&view) ==
        ELF_IDENT_BAD_MAGIC
    );
    identification[0] = 0x7f;

    identification[4] = 0x01;
    assert(
        elf_validate_identification(&view) ==
        ELF_IDENT_UNSUPPORTED_CLASS
    );
    identification[4] = 0x02;

    identification[5] = 0x02;
    assert(
        elf_validate_identification(&view) ==
        ELF_IDENT_UNSUPPORTED_ENCODING
    );
    identification[5] = 0x01;

    identification[6] = 0x00;
    assert(
        elf_validate_identification(&view) ==
        ELF_IDENT_UNSUPPORTED_VERSION
    );
    identification[6] = 0x01;

    assert(elf_validate_identification(&view) == ELF_IDENT_OK);
}

static void test_header_decoding(void) {
    uint8_t header_bytes[64] = {
        /* e_ident */
        0x7f, 'E', 'L', 'F',
        0x02, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,

        /* e_type, e_machine */
        0x02, 0x00,
        0x3e, 0x00,

        /* e_version */
        0x01, 0x00, 0x00, 0x00,

        /* e_entry = 0x401234 */
        0x34, 0x12, 0x40, 0x00,
        0x00, 0x00, 0x00, 0x00,

        /* e_phoff = 64 */
        0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,

        /* e_shoff = 4096 */
        0x00, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,

        /* e_flags */
        0x00, 0x00, 0x00, 0x00,

        /* e_ehsize, e_phentsize, e_phnum */
        0x40, 0x00,
        0x38, 0x00,
        0x03, 0x00,

        /* e_shentsize, e_shnum, e_shstrndx */
        0x40, 0x00,
        0x07, 0x00,
        0x06, 0x00
    };

    ByteView header_view = {
        .data = header_bytes,
        .size = sizeof(header_bytes)
    };

    Elf64Header header = {0};

    assert(elf_decode_header(&header_view, &header));

    assert(header.type == 2);
    assert(header.machine == 62);
    assert(header.version == 1);
    assert(header.entry == UINT64_C(0x401234));
    assert(header.program_header_offset == UINT64_C(64));
    assert(header.section_header_offset == UINT64_C(4096));
    assert(header.flags == UINT32_C(0));
    assert(header.header_size == UINT16_C(64));
    assert(header.program_header_entry_size == UINT16_C(56));
    assert(header.program_header_count == UINT16_C(3));
    assert(header.section_header_entry_size == UINT16_C(64));
    assert(header.section_header_count == UINT16_C(7));
    assert(header.section_name_table_index == UINT16_C(6));

    ByteView truncated_header = {
        .data = header_bytes,
        .size = 63
    };

    Elf64Header unchanged = {
        .type = UINT16_C(0xcccc),
        .entry = UINT64_C(0xcccccccccccccccc),
        .section_header_count = UINT16_C(0xcccc)
    };

    assert(!elf_decode_header(&truncated_header, &unchanged));
    assert(unchanged.type == UINT16_C(0xcccc));
    assert(unchanged.entry == UINT64_C(0xcccccccccccccccc));
    assert(unchanged.section_header_count == UINT16_C(0xcccc));
}

static void test_header_validation(void) {
    Elf64Header header = {
        .type = 2,
        .machine = 62,
        .version = 1,
        .header_size = 64
    };

    assert(elf_validate_header(&header) == ELF_HEADER_OK);

    header.type = 1;
    assert(elf_validate_header(&header) == ELF_HEADER_OK);

    header.type = 2;
    assert(elf_validate_header(&header) == ELF_HEADER_OK);

    header.type = 3;
    assert(elf_validate_header(&header) == ELF_HEADER_OK);

    header.type = 4;
    assert(
        elf_validate_header(&header) ==
        ELF_HEADER_UNSUPPORTED_TYPE
    );
    header.type = 2;

    header.machine = 3;
    assert(
        elf_validate_header(&header) ==
        ELF_HEADER_UNSUPPORTED_MACHINE
    );
    header.machine = 62;

    header.version = 0;
    assert(
        elf_validate_header(&header) ==
        ELF_HEADER_UNSUPPORTED_VERSION
    );
    header.version = 1;

    header.header_size = 63;
    assert(
        elf_validate_header(&header) ==
        ELF_HEADER_INVALID_SIZE
    );
    header.header_size = 64;

    assert(elf_validate_header(&header) == ELF_HEADER_OK);
}

static void test_program_header_layout(void) {
    uint8_t file_bytes[232] = {0};

    ByteView view = {
        .data = file_bytes,
        .size = sizeof(file_bytes)
    };

    Elf64Header header = {
        .program_header_offset = 64,
        .program_header_entry_size = 56,
        .program_header_count = 3
    };

    assert(
        elf_validate_layout(&view, &header) ==
        ELF_LAYOUT_OK
    );

    view.size = 231;

    assert(
        elf_validate_layout(&view, &header) ==
        ELF_LAYOUT_PROGRAM_HEADER_TABLE_OUT_OF_BOUNDS
    );

    view.size = sizeof(file_bytes);

    header.program_header_count = UINT16_MAX;

    assert(
        elf_validate_layout(&view, &header) ==
        ELF_LAYOUT_UNSUPPORTED_EXTENDED_NUMBERING
    );

    header.program_header_count = 3;

    header.program_header_entry_size = 55;

    assert(
        elf_validate_layout(&view, &header) ==
        ELF_LAYOUT_INVALID_PROGRAM_HEADER_ENTRY_SIZE
    );

    header.program_header_entry_size = 56;

    header.program_header_offset = UINT64_MAX;

    assert(
        elf_validate_layout(&view, &header) ==
        ELF_LAYOUT_PROGRAM_HEADER_TABLE_OUT_OF_BOUNDS
    );

    header.program_header_offset = 64;

    header.program_header_count = 0;
    header.program_header_offset = UINT64_MAX;
    header.program_header_entry_size = 0;

    assert(
        elf_validate_layout(&view, &header) ==
        ELF_LAYOUT_OK
    );

    header.program_header_count = 3;
    header.program_header_entry_size = 56;
    header.program_header_offset = 0;

    assert(
        elf_validate_layout(&view, &header) ==
        ELF_LAYOUT_INVALID_PROGRAM_HEADER_OFFSET
    );

    header.program_header_offset = 64;
}

static void test_section_header_layout(void) {
    uint8_t file_bytes[256] = {0};

    ByteView view = {
        .data = file_bytes,
        .size = sizeof(file_bytes)
    };

    Elf64Header header = {
        .section_header_offset = 64,
        .section_header_entry_size = 64,
        .section_header_count = 3,
        .section_name_table_index = 2
    };

    assert(
        elf_validate_layout(&view, &header) ==
        ELF_LAYOUT_OK
    );

    view.size = 255;
    assert(
        elf_validate_layout(&view, &header) ==
        ELF_LAYOUT_SECTION_HEADER_TABLE_OUT_OF_BOUNDS
    );
    view.size = sizeof(file_bytes);

    header.section_header_offset = 0;
    assert(
        elf_validate_layout(&view, &header) ==
        ELF_LAYOUT_INVALID_SECTION_HEADER_OFFSET
    );
    header.section_header_offset = 64;

    header.section_header_entry_size = 63;
    assert(
        elf_validate_layout(&view, &header) ==
        ELF_LAYOUT_INVALID_SECTION_HEADER_ENTRY_SIZE
    );
    header.section_header_entry_size = 64;

    header.section_name_table_index = 3;
    assert(
        elf_validate_layout(&view, &header) ==
        ELF_LAYOUT_INVALID_SECTION_NAME_TABLE_INDEX
    );

    header.section_name_table_index = UINT16_MAX;
    assert(
        elf_validate_layout(&view, &header) ==
        ELF_LAYOUT_UNSUPPORTED_EXTENDED_NUMBERING
    );

    header.section_name_table_index = 0;
    assert(
        elf_validate_layout(&view, &header) ==
        ELF_LAYOUT_OK
    );

    header.section_header_count = 0;
    header.section_header_offset = 64;

    assert(
        elf_validate_layout(&view, &header) ==
        ELF_LAYOUT_UNSUPPORTED_EXTENDED_NUMBERING
    );

    header.section_header_offset = 0;
    header.section_name_table_index = 1;

    assert(
        elf_validate_layout(&view, &header) ==
        ELF_LAYOUT_INVALID_SECTION_NAME_TABLE_INDEX
    );

    header.section_name_table_index = 0;

    assert(
        elf_validate_layout(&view, &header) ==
        ELF_LAYOUT_OK
    );
}

int main(void) {
    test_identification();
    test_header_decoding();
    test_header_validation();
    test_program_header_layout();
    test_section_header_layout();

    printf("All ELF parser tests passed.\n");

    return 0;
}
