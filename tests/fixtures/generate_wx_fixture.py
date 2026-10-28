from pathlib import Path
import struct

FILE_SIZE = 120

identification = (
    b"\x7fELF"
    + bytes([2, 1, 1, 0])
    + bytes(8)
)

elf_header = struct.pack(
    "<16sHHIQQQIHHHHHH",
    identification,
    2,          # executable
    62,         # x86-64
    1,          # ELF version
    0x400000,   # entry address
    64,         # program-header table offset
    0,          # no section-header table
    0,          # flags
    64,         # ELF header size
    56,         # program-header entry size
    1,          # one program header
    0,          # no section-header entry size
    0,          # no sections
    0           # no section-name table
)

program_header = struct.pack(
    "<IIQQQQQQ",
    1,          # PT_LOAD
    7,          # R | W | X
    0,          # segment begins at file offset 0
    0x400000,   # virtual address
    0x400000,   # physical address
    FILE_SIZE,  # file size
    FILE_SIZE,  # memory size
    0x1000      # alignment
)

fixture = elf_header + program_header

assert len(elf_header) == 64
assert len(program_header) == 56
assert len(fixture) == FILE_SIZE

output = Path(__file__).with_name("wx_load.elf")
output.write_bytes(fixture)

print(f"Wrote {len(fixture)} bytes to {output}")