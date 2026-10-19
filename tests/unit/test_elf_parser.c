#include "elf_parser.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
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

    printf("All ELF identification tests passed.\n");
    return 0;
}
