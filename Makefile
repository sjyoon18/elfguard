CC = clang
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -g -Iinclude
SANITIZER_FLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer

.PHONY: test test-sanitize clean

elfguard: src/main.c src/file_buffer.c include/file_buffer.h
	$(CC) $(CFLAGS) src/main.c src/file_buffer.c -o elfguard

test_byte_reader: tests/unit/test_byte_reader.c src/byte_reader.c include/byte_reader.h
	$(CC) $(CFLAGS) \
		tests/unit/test_byte_reader.c src/byte_reader.c \
		-o test_byte_reader

test_byte_reader_sanitize: tests/unit/test_byte_reader.c src/byte_reader.c include/byte_reader.h
	$(CC) $(CFLAGS) $(SANITIZER_FLAGS) \
		tests/unit/test_byte_reader.c src/byte_reader.c \
		-o test_byte_reader_sanitize

test: test_byte_reader
	./test_byte_reader

test-sanitize: test_byte_reader_sanitize
	./test_byte_reader_sanitize

clean:
	rm -f elfguard test_byte_reader test_byte_reader_sanitize
	rm -rf elfguard.dSYM test_byte_reader.dSYM test_byte_reader_sanitize.dSYM