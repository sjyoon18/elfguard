CC = clang
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -g -Iinclude

elfguard: src/main.c src/file_buffer.c include/file_buffer.h
	$(CC) $(CFLAGS) src/main.c src/file_buffer.c -o elfguard

test_byte_reader: tests/unit/test_byte_reader.c src/byte_reader.c include/byte_reader.h
	$(CC) $(CFLAGS) tests/unit/test_byte_reader.c src/byte_reader.c -o test_byte_reader

.PHONY: clean test

test: test_byte_reader
	./test_byte_reader

clean:
	rm -f elfguard test_byte_reader
	rm -rf elfguard.dSYM test_byte_reader.dSYM