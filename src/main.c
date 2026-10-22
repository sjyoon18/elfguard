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

    printf("%s: valid supported ELF64 file\n", argv[1]);

    file_buffer_destroy(&buffer);
    
    return EXIT_SUCCESS;
}
