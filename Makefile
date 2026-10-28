CC = clang
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -g -Iinclude
SANITIZER_FLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer

.PHONY: test test-sanitize test-integration clean

elfguard: src/main.c src/file_buffer.c src/byte_reader.c src/elf_parser.c include/file_buffer.h include/byte_reader.h include/elf_parser.h
	$(CC) $(CFLAGS) \
		src/main.c src/file_buffer.c src/byte_reader.c src/elf_parser.c \
		-o elfguard

test_byte_reader: tests/unit/test_byte_reader.c src/byte_reader.c include/byte_reader.h
	$(CC) $(CFLAGS) \
		tests/unit/test_byte_reader.c src/byte_reader.c \
		-o test_byte_reader

test_byte_reader_sanitize: tests/unit/test_byte_reader.c src/byte_reader.c include/byte_reader.h
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) \
		tests/unit/test_byte_reader.c src/byte_reader.c \
		-o test_byte_reader_sanitize

test_elf_parser: tests/unit/test_elf_parser.c src/elf_parser.c src/byte_reader.c include/elf_parser.h include/byte_reader.h
	$(CC) $(CFLAGS) \
		tests/unit/test_elf_parser.c \
		src/elf_parser.c src/byte_reader.c \
		-o test_elf_parser

test_elf_parser_sanitize: tests/unit/test_elf_parser.c src/elf_parser.c src/byte_reader.c include/elf_parser.h include/byte_reader.h
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) \
		tests/unit/test_elf_parser.c \
		src/elf_parser.c src/byte_reader.c \
		-o test_elf_parser_sanitize

test: test_byte_reader test_elf_parser
	./test_byte_reader
	./test_elf_parser

test-sanitize: test_byte_reader_sanitize test_elf_parser_sanitize
	./test_byte_reader_sanitize
	./test_elf_parser_sanitize

test-integration: elfguard
	python3 tests/integration/test_cli.py

clean:
	rm -f elfguard test_byte_reader test_byte_reader_sanitize test_elf_parser test_elf_parser_sanitize
	rm -rf elfguard.dSYM test_byte_reader.dSYM test_byte_reader_sanitize.dSYM test_elf_parser.dSYM test_elf_parser_sanitize.dSYM