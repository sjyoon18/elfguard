from pathlib import Path
import struct

ELF_HEADER_SIZE = 64
SECTION_HEADER_SIZE = 64
SECTION_HEADER_COUNT = 2

SECTION_HEADER_TABLE_OFFSET = ELF_HEADER_SIZE
STRING_TABLE_OFFSET = (
    SECTION_HEADER_TABLE_OFFSET
    + SECTION_HEADER_SIZE * SECTION_HEADER_COUNT
)

# Valid initial empty string, followed by an unterminated name.
string_table = b"\x00bad"

identification = (
    b"\x7fELF"
    + bytes([2, 1, 1, 0])
    + bytes(8)
)

elf_header = struct.pack(
    "<16sHHIQQQIHHHHHH",
    identification,
    1,                              # ET_REL
    62,                             # x86-64
    1,                              # ELF version
    0,                              # no entry point
    0,                              # no program-header table
    SECTION_HEADER_TABLE_OFFSET,
    0,                              # flags
    ELF_HEADER_SIZE,
    0,                              # no program-header entry size
    0,                              # no program headers
    SECTION_HEADER_SIZE,
    SECTION_HEADER_COUNT,
    1                               # section #1 is name table
)

null_section = bytes(SECTION_HEADER_SIZE)

name_table_section = struct.pack(
    "<IIQQQQIIQQ",
    1,                              # name offset: "bad"
    3,                              # SHT_STRTAB
    0,                              # flags
    0,                              # virtual address
    STRING_TABLE_OFFSET,
    len(string_table),
    0,                              # link
    0,                              # info
    1,                              # alignment
    0                               # entry size
)

fixture = (
    elf_header
    + null_section
    + name_table_section
    + string_table
)

assert len(elf_header) == ELF_HEADER_SIZE
assert len(null_section) == SECTION_HEADER_SIZE
assert len(name_table_section) == SECTION_HEADER_SIZE
assert len(fixture) == STRING_TABLE_OFFSET + len(string_table)

output = Path(__file__).with_name(
    "unterminated_section_name.elf"
)

output.write_bytes(fixture)

print(f"Wrote {len(fixture)} bytes to {output}")