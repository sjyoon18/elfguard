#include "elf_parser.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(
    const uint8_t *data,
    size_t size
) {
    ByteView view = {
        .data = data,
        .size = size
    };

    if (elf_validate_identification(&view) != ELF_IDENT_OK) {
        return 0;
    }

    Elf64Header header = {0};

    if (!elf_decode_header(&view, &header)) {
        return 0;
    }

    if (elf_validate_header(&header) != ELF_HEADER_OK) {
        return 0;
    }

    if (elf_validate_layout(&view, &header) != ELF_LAYOUT_OK) {
        return 0;
    }

    for (uint16_t index = 0;
         index < header.program_header_count;
         index++) {
        Elf64ProgramHeader program_header = {0};

        if (!elf_decode_program_header(
                &view,
                &header,
                index,
                &program_header
            )) {
            return 0;
        }

        if (elf_validate_program_header(
                &view,
                &program_header
            ) != ELF_PROGRAM_HEADER_OK) {
            return 0;
        }

        (void)elf_program_header_is_writable_executable(
            &program_header
        );
    }

    bool has_section_name_table =
        header.section_name_table_index != 0;

    Elf64SectionHeader section_name_table = {0};

    if (has_section_name_table) {
        if (!elf_decode_section_header(
                &view,
                &header,
                header.section_name_table_index,
                &section_name_table
            )) {
            return 0;
        }

        if (elf_validate_section_header(
                &view,
                &section_name_table
            ) != ELF_SECTION_HEADER_OK) {
            return 0;
        }
    }

    for (uint16_t index = 0;
        index < header.section_header_count;
        index++) {
        Elf64SectionHeader section_header = {0};

        if (!elf_decode_section_header(
                &view,
                &header,
                index,
                &section_header
            )) {
            return 0;
        }

        if (elf_validate_section_header(
                &view,
                &section_header
            ) != ELF_SECTION_HEADER_OK) {
            return 0;
        }

        if (has_section_name_table) {
            ByteView section_name = {0};

            if (elf_resolve_section_name(
                    &view,
                    &section_name_table,
                    &section_header,
                    &section_name
                ) != ELF_SECTION_NAME_OK) {
                return 0;
            }
        }
    }

    return 0;
}
