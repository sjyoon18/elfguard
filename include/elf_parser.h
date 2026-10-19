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

ElfIdentStatus elf_validate_identification(const ByteView *view);

#endif
