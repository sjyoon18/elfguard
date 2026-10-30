#include "file_buffer.h"
#include "elf_parser.h"

#include <stdio.h>
#include <stdlib.h>

static const char *ident_status_message(ElfIdentStatus status) {
    switch (status) {
        case ELF_IDENT_OK:
            return "supported ELF identification";
        case ELF_IDENT_TRUNCATED:
            return "truncated ELF identification";
        case ELF_IDENT_BAD_MAGIC:
            return "not an ELF file";
        case ELF_IDENT_UNSUPPORTED_CLASS:
            return "unsupported ELF class";
        case ELF_IDENT_UNSUPPORTED_ENCODING:
            return "unsupported ELF byte order";
        case ELF_IDENT_UNSUPPORTED_VERSION:
            return "unsupported ELF version";
        default:
            return "unknown ELF identification error";
    }
}

static const char *header_status_message(ElfHeaderStatus status) {
    switch (status) {
        case ELF_HEADER_OK:
            return "valid ELF64 header";
        case ELF_HEADER_UNSUPPORTED_TYPE:
            return "unsupported ELF file type";
        case ELF_HEADER_UNSUPPORTED_MACHINE:
            return "unsupported machine architecture";
        case ELF_HEADER_UNSUPPORTED_VERSION:
            return "unsupported ELF header version";
        case ELF_HEADER_INVALID_SIZE:
            return "invalid ELF header size";
        default:
            return "unknown ELF header error";
    }
}

static const char *layout_status_message(ElfLayoutStatus status) {
    switch (status) {
        case ELF_LAYOUT_OK:
            return "valid ELF layout";
        case ELF_LAYOUT_UNSUPPORTED_EXTENDED_NUMBERING:
            return "unsupported ELF extended numbering";
        case ELF_LAYOUT_INVALID_PROGRAM_HEADER_OFFSET:
            return "invalid program-header table offset";
        case ELF_LAYOUT_INVALID_PROGRAM_HEADER_ENTRY_SIZE:
            return "invalid program-header entry size";
        case ELF_LAYOUT_PROGRAM_HEADER_TABLE_OUT_OF_BOUNDS:
            return "program-header table extends beyond file";
        case ELF_LAYOUT_INVALID_SECTION_HEADER_OFFSET:
            return "invalid section-header table offset";
        case ELF_LAYOUT_INVALID_SECTION_HEADER_ENTRY_SIZE:
            return "invalid section-header entry size";
        case ELF_LAYOUT_SECTION_HEADER_TABLE_OUT_OF_BOUNDS:
            return "section-header table extends beyond file";
        case ELF_LAYOUT_INVALID_SECTION_NAME_TABLE_INDEX:
            return "invalid section-name table index";
        default:
            return "unknown ELF layout error";
    }
}

static const char *section_header_status_message(
    ElfSectionHeaderStatus status
) {
    switch (status) {
        case ELF_SECTION_HEADER_OK:
            return "valid section header";
        case ELF_SECTION_HEADER_FILE_RANGE_OUT_OF_BOUNDS:
            return "section file range extends beyond file";
        case ELF_SECTION_HEADER_INVALID_ALIGNMENT:
            return "invalid section alignment";
        case ELF_SECTION_HEADER_ADDRESS_ALIGNMENT_MISMATCH:
            return "section address is misaligned";
        case ELF_SECTION_HEADER_SIZE_NOT_MULTIPLE_OF_ENTRY_SIZE:
            return "section size is not a multiple of entry size";
        default:
            return "unknown section-header error";
    }
}

static const char *program_header_status_message(
    ElfProgramHeaderStatus status
) {
    switch (status) {
        case ELF_PROGRAM_HEADER_OK:
            return "valid program header";
        case ELF_PROGRAM_HEADER_FILE_RANGE_OUT_OF_BOUNDS:
            return "segment file range extends beyond file";
        case ELF_PROGRAM_HEADER_MEMORY_SIZE_TOO_SMALL:
            return "loadable segment memory size is smaller than file size";
        case ELF_PROGRAM_HEADER_INVALID_ALIGNMENT:
            return "invalid segment alignment";
        case ELF_PROGRAM_HEADER_ALIGNMENT_MISMATCH:
            return "segment file offset and virtual address are misaligned";
        default:
            return "unknown program-header error";
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    FileBuffer buffer = {0};

    if (file_buffer_load(argv[1], &buffer) == -1) {
        perror(argv[1]);
        return EXIT_FAILURE;
    }

    ByteView view = {
        .data = buffer.data,
        .size = buffer.size
    };

    ElfIdentStatus ident_status = elf_validate_identification(&view);

    if (ident_status != ELF_IDENT_OK) {
        fprintf(
            stderr,
            "%s: %s\n",
            argv[1],
            ident_status_message(ident_status)
        );

        file_buffer_destroy(&buffer);
        return EXIT_FAILURE;
    }

    Elf64Header header = {0};

    if (!elf_decode_header(&view, &header)) {
        fprintf(
            stderr,
            "%s: truncated ELF64 header\n",
            argv[1]
        );

        file_buffer_destroy(&buffer);
        return EXIT_FAILURE;
    }

    ElfHeaderStatus header_status = elf_validate_header(&header);

    if (header_status != ELF_HEADER_OK) {
        fprintf(
            stderr,
            "%s: %s\n",
            argv[1],
            header_status_message(header_status)
        );

        file_buffer_destroy(&buffer);
        return EXIT_FAILURE;
    }

    ElfLayoutStatus layout_status = elf_validate_layout(&view, &header);

    if (layout_status != ELF_LAYOUT_OK) {
        fprintf(
            stderr,
            "%s: %s\n",
            argv[1],
            layout_status_message(layout_status)
        );

        file_buffer_destroy(&buffer);
        return EXIT_FAILURE;
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
            fprintf(
                stderr,
                "%s: program header %u: failed to decode\n",
                argv[1],
                (unsigned int)index
            );

            file_buffer_destroy(&buffer);
            return EXIT_FAILURE;
        }

        ElfProgramHeaderStatus program_status =
            elf_validate_program_header(
                &view,
                &program_header
            );
        
        if (program_status != ELF_PROGRAM_HEADER_OK) {
            fprintf(
                stderr,
                "%s: program header %u: %s\n",
                argv[1],
                (unsigned int)index,
                program_header_status_message(program_status)
            );

            file_buffer_destroy(&buffer);
            return EXIT_FAILURE;
        }

        if (elf_program_header_is_writable_executable(
                &program_header
            )) {
            fprintf(
                stderr,
                "%s: warning: program header %u has "
                "writable and executable permissions\n",
                argv[1],
                (unsigned int)index
            );
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
            fprintf(
                stderr,
                "%s: section header %u: failed to decode\n",
                argv[1],
                (unsigned int)index
            );

            file_buffer_destroy(&buffer);
            return EXIT_FAILURE;
        }

        ElfSectionHeaderStatus section_status =
            elf_validate_section_header(
                &view,
                &section_header
            );

        if (section_status != ELF_SECTION_HEADER_OK) {
            fprintf(
                stderr,
                "%s: section header %u: %s\n",
                argv[1],
                (unsigned int)index,
                section_header_status_message(section_status)
            );

            file_buffer_destroy(&buffer);
            return EXIT_FAILURE;
        }
    }

    printf("%s: valid supported ELF64 file\n", argv[1]);

    file_buffer_destroy(&buffer);
    
    return EXIT_SUCCESS;
}
