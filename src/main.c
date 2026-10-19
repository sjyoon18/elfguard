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

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    printf("%s\n", argv[1]);

    FileBuffer buffer = {0};

    if (file_buffer_load(argv[1], &buffer) == -1) {
        perror(argv[1]);
        return EXIT_FAILURE;
    }

    ByteView view = {
        .data = buffer.data,
        .size = buffer.size
    };

    ElfIdentStatus status = elf_validate_identification(&view);

    if (status != ELF_IDENT_OK) {
        fprintf(
            stderr,
            "%s: %s\n",
            argv[1],
            ident_status_message(status)
        );

        file_buffer_destroy(&buffer);
        return EXIT_FAILURE;
    }

    printf("%s: supported ELF64 little-endian file\n", argv[1]);

    file_buffer_destroy(&buffer);
    
    return EXIT_SUCCESS;
}
